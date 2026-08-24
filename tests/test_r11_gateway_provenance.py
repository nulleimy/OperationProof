from __future__ import annotations

from datetime import UTC, datetime

import httpx
from fastapi.testclient import TestClient

import operationproof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS
from operationproof.attested_gateway import create_attested_gateway_app

UPSTREAM_ID = "service-r11"
BODY = b'{"hello":"r11"}'
HEADERS = {"content-type": "application/json"}
PATH = "/deploy"
QUERY = "dry=0"
NOW = datetime(2026, 8, 24, 4, 0, tzinfo=UTC)
SECRET = b"r11-gateway-reference-secret-material!!"


def _registry() -> operationproof.ProviderTrustRegistry:
    registry = operationproof.ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        def verifier(
            _envelope: object,
            _context: object,
            *,
            accepted: bool = True,
        ) -> bool:
            return accepted

        registry.register(
            layer=layer,
            provider=f"r11:{layer.value}",
            verifier=verifier,
        )
    return registry


def _proof() -> dict[str, object]:
    operation_id = "op-r11-gateway"
    target_digest = operationproof.gateway_target_digest(
        upstream_id=UPSTREAM_ID,
        method="POST",
        path=PATH,
        query=QUERY,
        headers=HEADERS,
        body=BODY,
    )
    subject = operationproof.OperationSubject(
        operation_id=operation_id,
        actor_digest=sha256_digest({"actor": "r11"}),
        intent_digest=sha256_digest({"intent": "deploy"}),
        target_digest=target_digest,
        state_digest=sha256_digest({"state": "revision-r11"}),
    )
    evidence = [
        operationproof.EvidenceEnvelope(
            layer=layer,
            provider=f"r11:{layer.value}",
            operation_id=operation_id,
            decision="native-ok",
            verdict=operationproof.Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"evidence": layer.value}),
            issued_at="2026-08-24T03:00:00+00:00",
            expires_at="2030-01-01T00:00:00+00:00",
            metadata={"layer": layer.value},
        )
        for layer in PRE_LAYERS
    ]
    return operationproof.build_pre_proof(operation_id, evidence, subject=subject)


def _signer() -> operationproof.HMACSHA256Signer:
    return operationproof.HMACSHA256Signer(
        issuer_id="issuer:gateway",
        key_id="key:gateway",
        secret=SECRET,
    )


def _verifier() -> operationproof.HMACSHA256Verifier:
    return operationproof.HMACSHA256Verifier(
        issuer_id="issuer:gateway",
        key_id="key:gateway",
        secret=SECRET,
    )


def _recorder(
    store: operationproof.AttestationStore,
    telemetry: operationproof.TelemetrySink | None = None,
) -> operationproof.ProvenanceRecorder:
    return operationproof.ProvenanceRecorder(
        signer=_signer(),
        verifier=_verifier(),
        store=store,
        telemetry_sink=telemetry,
        clock=lambda: NOW,
    )


def _success_client(seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(202, content=b"upstream-ok", headers={"content-type": "text/plain"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _failure_client() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _app(
    *,
    provenance_store: operationproof.AttestationStore,
    telemetry: operationproof.TelemetrySink | None = None,
    upstream_client: httpx.AsyncClient,
):
    return create_attested_gateway_app(
        _registry(),
        operationproof.MemoryGatewayAdmissionStore(),
        _recorder(provenance_store, telemetry),
        upstream_base_url="https://upstream.test",
        upstream_id=UPSTREAM_ID,
        forward_headers=("content-type",),
        clock=lambda: NOW,
        http_client=upstream_client,
    )


def _admit(client: TestClient) -> str:
    proof = _proof()
    response = client.post(
        "/v1/admissions",
        content=operationproof.canonical_proof_json(proof),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 201, response.text
    token = response.json()["admission_token"]
    assert isinstance(token, str) and token
    return token


def _event_types(store: operationproof.MemoryAttestationStore) -> list[str]:
    return [
        item["attestation"]["artifact_type"]
        for item in store.records("op-r11-gateway")
    ]


def test_attested_gateway_success_lifecycle_and_chain() -> None:
    seen: list[httpx.Request] = []
    store = operationproof.MemoryAttestationStore()
    telemetry = operationproof.MemoryTelemetrySink()
    app = _app(
        provenance_store=store,
        telemetry=telemetry,
        upstream_client=_success_client(seen),
    )
    with TestClient(app) as client:
        token = _admit(client)
        response = client.post(
            "/v1/proxy/deploy?dry=0",
            content=BODY,
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/json",
            },
        )

    assert response.status_code == 202
    assert len(seen) == 1
    assert _event_types(store) == [
        "proof_assessed",
        "admission_created",
        "admission_consumed",
        "upstream_dispatched",
        "upstream_completed",
    ]
    assert [event["event_type"] for event in telemetry.events] == _event_types(store)

    proof = _proof()
    verifier = _verifier()
    chain = operationproof.verify_provenance_chain(
        list(store.records("op-r11-gateway")),
        verifiers={(verifier.issuer_id, verifier.algorithm, verifier.key_id): verifier},
        expected_operation_id="op-r11-gateway",
        expected_subject_digest=proof["subject_digest"],
        expected_proof_digest=proof["proof_digest"],
        now=NOW,
    )
    assert chain.valid is True


def test_attested_gateway_upstream_failure_lifecycle() -> None:
    store = operationproof.MemoryAttestationStore()
    app = _app(
        provenance_store=store,
        upstream_client=_failure_client(),
    )
    with TestClient(app) as client:
        token = _admit(client)
        response = client.post(
            "/v1/proxy/deploy?dry=0",
            content=BODY,
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/json",
            },
        )

    assert response.status_code == 502
    assert response.json()["reason_codes"] == ["UPSTREAM_REQUEST_FAILED"]
    assert _event_types(store) == [
        "proof_assessed",
        "admission_created",
        "admission_consumed",
        "upstream_dispatched",
        "upstream_failed",
    ]


class _FailingStore(operationproof.AttestationStore):
    def head(self, operation_id: str):
        del operation_id
        return None

    def append(
        self,
        signed_attestation,
        *,
        expected_sequence: int,
        expected_previous_attestation_digest: str,
    ):
        del signed_attestation, expected_sequence, expected_previous_attestation_digest
        raise operationproof.AttestationStoreError("down")

    def read(self, operation_id: str, sequence: int):
        del operation_id, sequence
        return None


def test_required_gateway_provenance_failure_is_fail_closed_before_admission() -> None:
    app = _app(
        provenance_store=_FailingStore(),
        upstream_client=_success_client([]),
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/admissions",
            content=operationproof.canonical_proof_json(_proof()),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 503
    assert response.json()["reason_codes"] == ["PROVENANCE_PERSISTENCE_FAILED"]


def test_client_cannot_select_provenance_signer_or_issuer() -> None:
    store = operationproof.MemoryAttestationStore()
    app = _app(
        provenance_store=store,
        upstream_client=_success_client([]),
    )
    with TestClient(app) as client:
        token = _admit(client)
        response = client.post(
            "/v1/proxy/deploy?dry=0",
            content=BODY,
            headers={
                "x-operationproof-admission": token,
                "content-type": "application/json",
                "x-operationproof-issuer": "attacker",
            },
        )

    assert response.status_code == 400
    assert response.json()["reason_codes"] == ["RESERVED_OPERATIONPROOF_HEADER"]
