from __future__ import annotations

from datetime import UTC, datetime

import httpx
from fastapi.testclient import TestClient

import operationproof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS
from operationproof.gateway import create_gateway_app

_UPSTREAM_ID = "service-a"
_BODY = b'{"hello":"world"}'
_HEADERS = {"content-type": "application/json"}
_PATH = "/deploy"
_QUERY = "dry=0"


def _registry(*, reject_layer: str | None = None) -> operationproof.ProviderTrustRegistry:
    registry = operationproof.ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        def verifier(
            _envelope: object,
            _context: object,
            *,
            accepted: bool = layer.value != reject_layer,
        ) -> bool:
            return accepted

        registry.register(
            layer=layer,
            provider=f"gw:{layer.value}",
            verifier=verifier,
        )
    return registry


def _proof(
    *,
    body: bytes = _BODY,
    subject_bound: bool = True,
    missing_expiry_layer: str | None = None,
) -> dict[str, object]:
    operation_id = "op-r10"
    target_digest = operationproof.gateway_target_digest(
        upstream_id=_UPSTREAM_ID,
        method="POST",
        path=_PATH,
        query=_QUERY,
        headers=_HEADERS,
        body=body,
    )
    subject = operationproof.OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "gateway-user"}),
        intent_digest=sha256_digest({"intent": "deploy"}),
        target_digest=target_digest,
        state_digest=sha256_digest({"state": "revision-1"}),
    )
    evidence = [
        operationproof.EvidenceEnvelope(
            layer=layer,
            provider=f"gw:{layer.value}",
            operation_id=operation_id,
            decision="native-ok",
            verdict=operationproof.Verdict.PASS,
            subject_digest=(subject.digest if subject_bound else sha256_digest({"layer": layer.value})),
            evidence_digest=sha256_digest({"evidence": layer.value}),
            issued_at="2026-08-24T00:00:00+00:00",
            expires_at=(
                None
                if layer.value == missing_expiry_layer
                else "2030-01-01T00:00:00+00:00"
            ),
            metadata={"layer": layer.value},
        )
        for layer in PRE_LAYERS
    ]
    return operationproof.build_pre_proof(
        operation_id,
        evidence,
        subject=subject if subject_bound else None,
    )


def _upstream_client(seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            202,
            content=b"upstream-ok",
            headers={"content-type": "text/plain", "server": "hidden"},
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _app(
    *,
    registry: operationproof.ProviderTrustRegistry | None = None,
    store: operationproof.GatewayAdmissionStore | None = None,
    seen: list[httpx.Request] | None = None,
):
    seen_requests = seen if seen is not None else []
    return create_gateway_app(
        registry or _registry(),
        store or operationproof.MemoryGatewayAdmissionStore(),
        upstream_base_url="https://upstream.test",
        upstream_id=_UPSTREAM_ID,
        forward_headers=("content-type",),
        clock=lambda: datetime(2026, 8, 24, 0, 30, tzinfo=UTC),
        http_client=_upstream_client(seen_requests),
    )


def _admit(client: TestClient, proof: dict[str, object]) -> str:
    response = client.post(
        "/v1/admissions",
        content=operationproof.canonical_proof_json(proof),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 201, response.text
    token = response.json()["admission_token"]
    assert isinstance(token, str) and token
    return token


def test_gateway_target_digest_is_deterministic_and_request_specific() -> None:
    first = operationproof.gateway_target_digest(
        upstream_id=_UPSTREAM_ID,
        method="post",
        path=_PATH,
        query=_QUERY,
        headers={"Content-Type": "application/json"},
        body=_BODY,
    )
    second = operationproof.gateway_target_digest(
        upstream_id=_UPSTREAM_ID,
        method="POST",
        path=_PATH,
        query=_QUERY,
        headers=_HEADERS,
        body=_BODY,
    )
    changed = operationproof.gateway_target_digest(
        upstream_id=_UPSTREAM_ID,
        method="POST",
        path=_PATH,
        query=_QUERY,
        headers=_HEADERS,
        body=b"different",
    )

    assert first == second
    assert first != changed


def test_gateway_target_rejects_path_traversal_and_internal_headers() -> None:
    try:
        operationproof.gateway_target_digest(
            upstream_id=_UPSTREAM_ID,
            method="GET",
            path="/a/../admin",
        )
    except operationproof.GatewayTargetError as exc:
        assert str(exc) == "GATEWAY_PATH_TRAVERSAL_FORBIDDEN"
    else:
        raise AssertionError("expected path traversal rejection")

    try:
        operationproof.canonical_gateway_headers({"X-OperationProof-Proof-Digest": "attacker"})
    except operationproof.GatewayTargetError as exc:
        assert str(exc) == "FORBIDDEN_GATEWAY_HEADER"
    else:
        raise AssertionError("expected internal header rejection")


def test_memory_admission_store_rejects_proof_replay_and_consumes_token_once() -> None:
    store = operationproof.MemoryGatewayAdmissionStore(max_records=2)
    record = operationproof.GatewayAdmissionRecord(
        operation_id="op-r10-store",
        proof_digest=sha256_digest({"proof": 1}),
        subject_digest=sha256_digest({"subject": 1}),
        target_digest=sha256_digest({"target": 1}),
        issued_at="2026-08-24T00:00:00+00:00",
        expires_at="2026-08-24T00:01:00+00:00",
    )
    token = store.reserve(record)

    try:
        store.reserve(record)
    except operationproof.GatewayAdmissionStoreError as exc:
        assert str(exc) == "PROOF_REPLAY_DETECTED"
    else:
        raise AssertionError("expected proof replay rejection")

    assert store.consume(token) == record
    assert store.consume(token) is None


def test_trusted_pre_v2_admission_forwards_only_exact_bound_request() -> None:
    seen: list[httpx.Request] = []
    app = _app(seen=seen)

    with TestClient(app) as client:
        token = _admit(client, _proof())
        response = client.post(
            "/v1/proxy/deploy?dry=0",
            content=_BODY,
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/json",
            },
        )

    assert response.status_code == 202
    assert response.content == b"upstream-ok"
    assert response.headers["content-type"].startswith("text/plain")
    assert "server" not in response.headers
    assert len(seen) == 1
    forwarded = seen[0]
    assert str(forwarded.url) == "https://upstream.test/deploy?dry=0"
    assert forwarded.content == _BODY
    assert forwarded.headers["x-operationproof-operation-id"] == "op-r10"
    assert forwarded.headers["x-operationproof-gateway-contract"] == "operationproof.gateway.v1"


def test_target_mismatch_burns_one_time_token_before_forward() -> None:
    seen: list[httpx.Request] = []
    app = _app(seen=seen)

    with TestClient(app) as client:
        token = _admit(client, _proof())
        mismatch = client.post(
            "/v1/proxy/deploy?dry=0",
            content=b"tampered",
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/json",
            },
        )
        retry = client.post(
            "/v1/proxy/deploy?dry=0",
            content=_BODY,
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/json",
            },
        )

    assert mismatch.status_code == 403
    assert mismatch.json()["reason_codes"] == ["GATEWAY_TARGET_DIGEST_MISMATCH"]
    assert retry.status_code == 401
    assert retry.json()["reason_codes"] == ["ADMISSION_TOKEN_INVALID_OR_CONSUMED"]
    assert seen == []


def test_same_pre_proof_cannot_be_admitted_twice() -> None:
    app = _app()
    proof = _proof()

    with TestClient(app) as client:
        _admit(client, proof)
        replay = client.post(
            "/v1/admissions",
            content=operationproof.canonical_proof_json(proof),
            headers={"content-type": "application/json"},
        )

    assert replay.status_code == 409
    assert replay.json()["reason_codes"] == ["PROOF_REPLAY_DETECTED"]


def test_gateway_rejects_untrusted_v1_and_nonexpiring_pre_proofs() -> None:
    untrusted = _app(registry=_registry(reject_layer="authorization"))
    with TestClient(untrusted) as client:
        response = client.post(
            "/v1/admissions",
            content=operationproof.canonical_proof_json(_proof()),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 403
    assert response.json()["assessment"]["accepted"] is False

    v1_app = _app()
    with TestClient(v1_app) as client:
        response = client.post(
            "/v1/admissions",
            content=operationproof.canonical_proof_json(_proof(subject_bound=False)),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 403
    assert response.json()["reason_codes"] == ["GATEWAY_REQUIRES_PROOF_V2"]

    expiry_app = _app()
    with TestClient(expiry_app) as client:
        response = client.post(
            "/v1/admissions",
            content=operationproof.canonical_proof_json(
                _proof(missing_expiry_layer="resource")
            ),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 403
    assert response.json()["reason_codes"] == ["GATEWAY_EVIDENCE_EXPIRY_REQUIRED"]


def test_client_cannot_inject_operationproof_headers_to_upstream() -> None:
    seen: list[httpx.Request] = []
    app = _app(seen=seen)

    with TestClient(app) as client:
        token = _admit(client, _proof())
        response = client.post(
            "/v1/proxy/deploy?dry=0",
            content=_BODY,
            headers={
                "x-operationproof-admission": token,
                "x-operationproof-operation-id": "attacker",
                "content-type": "application/json",
            },
        )

    assert response.status_code == 400
    assert response.json()["reason_codes"] == ["RESERVED_OPERATIONPROOF_HEADER"]
    assert seen == []
