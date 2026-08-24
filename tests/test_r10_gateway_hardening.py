from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

import operationproof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS
from operationproof.gateway import GatewayConfigError, create_gateway_app

_UPSTREAM_ID = "service-hardening"
_BODY = b"payload"


def _registry() -> operationproof.ProviderTrustRegistry:
    registry = operationproof.ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        registry.register(
            layer=layer,
            provider=f"hardening:{layer.value}",
            verifier=lambda _envelope, _context: True,
        )
    return registry


def _proof(*, operation_id: str = "op-r10-hardening") -> dict[str, object]:
    target_digest = operationproof.gateway_target_digest(
        upstream_id=_UPSTREAM_ID,
        method="POST",
        path="/deploy",
        headers={"content-type": "application/octet-stream"},
        body=_BODY,
    )
    subject = operationproof.OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "hardening"}),
        intent_digest=sha256_digest({"intent": "dispatch"}),
        target_digest=target_digest,
        state_digest=sha256_digest({"state": "r10"}),
    )
    evidence = [
        operationproof.EvidenceEnvelope(
            layer=layer,
            provider=f"hardening:{layer.value}",
            operation_id=operation_id,
            decision="native-ok",
            verdict=operationproof.Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"evidence": layer.value, "operation": operation_id}),
            issued_at="2026-08-24T00:00:00+00:00",
            expires_at="2030-01-01T00:00:00+00:00",
            metadata={"layer": layer.value},
        )
        for layer in PRE_LAYERS
    ]
    return operationproof.build_pre_proof(operation_id, evidence, subject=subject)


def _post_admission(client: TestClient, proof: dict[str, object]):
    return client.post(
        "/v1/admissions",
        content=operationproof.canonical_proof_json(proof),
        headers={"content-type": "application/json"},
    )


def _mock_client(seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_delimiter_only_query_or_fragment_is_invalid_upstream_configuration() -> None:
    for upstream in ("https://upstream.test?", "https://upstream.test#"):
        with pytest.raises(GatewayConfigError, match="INVALID_UPSTREAM_BASE_URL"):
            create_gateway_app(
                _registry(),
                operationproof.MemoryGatewayAdmissionStore(),
                upstream_base_url=upstream,
                upstream_id=_UPSTREAM_ID,
            )


def test_admission_expiry_is_rechecked_immediately_before_upstream_dispatch() -> None:
    seen: list[httpx.Request] = []
    times = iter(
        (
            datetime(2026, 8, 24, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 24, 0, 0, 10, tzinfo=UTC),
            datetime(2026, 8, 24, 0, 0, 31, tzinfo=UTC),
        )
    )
    app = create_gateway_app(
        _registry(),
        operationproof.MemoryGatewayAdmissionStore(),
        upstream_base_url="https://upstream.test",
        upstream_id=_UPSTREAM_ID,
        admission_ttl_seconds=30,
        forward_headers=("content-type",),
        clock=lambda: next(times),
        http_client=_mock_client(seen),
    )

    with TestClient(app) as client:
        admission = _post_admission(client, _proof())
        assert admission.status_code == 201
        token = admission.json()["admission_token"]
        response = client.post(
            "/v1/proxy/deploy",
            content=_BODY,
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/octet-stream",
            },
        )

    assert response.status_code == 401
    assert response.json()["reason_codes"] == ["ADMISSION_TOKEN_EXPIRED"]
    assert seen == []


def test_gateway_rejects_naive_runtime_clock_fail_closed() -> None:
    app = create_gateway_app(
        _registry(),
        operationproof.MemoryGatewayAdmissionStore(),
        upstream_base_url="https://upstream.test",
        upstream_id=_UPSTREAM_ID,
        clock=lambda: datetime(2026, 8, 24, 0, 0, 0),  # noqa: DTZ001 - intentional
    )

    with TestClient(app) as client:
        response = _post_admission(client, _proof())

    assert response.status_code == 503
    assert response.json()["reason_codes"] == ["INVALID_GATEWAY_CLOCK"]


class _InvalidTokenStore(operationproof.GatewayAdmissionStore):
    def reserve(self, record: operationproof.GatewayAdmissionRecord) -> str:
        assert isinstance(record, operationproof.GatewayAdmissionRecord)
        return " bad-token "

    def consume(self, token: str) -> operationproof.GatewayAdmissionRecord | None:
        return None


class _InvalidRecordStore(operationproof.GatewayAdmissionStore):
    def reserve(self, record: operationproof.GatewayAdmissionRecord) -> str:
        assert isinstance(record, operationproof.GatewayAdmissionRecord)
        return "valid-token"

    def consume(self, token: str) -> operationproof.GatewayAdmissionRecord | None:
        assert token == "valid-token"
        return object()  # type: ignore[return-value]


def test_external_store_invalid_token_is_not_exposed_as_capability() -> None:
    app = create_gateway_app(
        _registry(),
        _InvalidTokenStore(),
        upstream_base_url="https://upstream.test",
        upstream_id=_UPSTREAM_ID,
        clock=lambda: datetime(2026, 8, 24, 0, 0, 0, tzinfo=UTC),
    )

    with TestClient(app) as client:
        response = _post_admission(client, _proof())

    assert response.status_code == 503
    assert response.json()["reason_codes"] == ["INVALID_ADMISSION_TOKEN_FROM_STORE"]


def test_external_store_invalid_consumed_record_fails_closed_before_request_work() -> None:
    seen: list[httpx.Request] = []
    app = create_gateway_app(
        _registry(),
        _InvalidRecordStore(),
        upstream_base_url="https://upstream.test",
        upstream_id=_UPSTREAM_ID,
        clock=lambda: datetime(2026, 8, 24, 0, 0, 0, tzinfo=UTC),
        http_client=_mock_client(seen),
    )

    with TestClient(app) as client:
        admission = _post_admission(client, _proof())
        assert admission.status_code == 201
        response = client.post(
            "/v1/proxy/deploy",
            content=_BODY,
            headers={
                "x-operationproof-admission": "valid-token",
                "content-type": "application/octet-stream",
            },
        )

    assert response.status_code == 503
    assert response.json()["reason_codes"] == ["INVALID_ADMISSION_RECORD_FROM_STORE"]
    assert seen == []


def test_memory_store_rejects_different_proof_for_same_exact_operation() -> None:
    store = operationproof.MemoryGatewayAdmissionStore()
    first = operationproof.GatewayAdmissionRecord(
        operation_id="same-operation",
        proof_digest=sha256_digest({"proof": 1}),
        subject_digest=sha256_digest({"subject": 1}),
        target_digest=sha256_digest({"target": 1}),
        issued_at="2026-08-24T00:00:00+00:00",
        expires_at="2026-08-24T00:01:00+00:00",
    )
    second = operationproof.GatewayAdmissionRecord(
        operation_id="same-operation",
        proof_digest=sha256_digest({"proof": 2}),
        subject_digest=sha256_digest({"subject": 2}),
        target_digest=sha256_digest({"target": 2}),
        issued_at="2026-08-24T00:00:01+00:00",
        expires_at="2026-08-24T00:01:00+00:00",
    )
    store.reserve(first)

    with pytest.raises(operationproof.GatewayAdmissionStoreError, match="PROOF_REPLAY_DETECTED"):
        store.reserve(second)
