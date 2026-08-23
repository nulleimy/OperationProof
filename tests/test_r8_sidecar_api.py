from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from operationproof.builder import build_pre_proof
from operationproof.canonical import canonical_json_bytes, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Verdict
from operationproof.sidecar import MAX_CONFIGURED_BODY_BYTES, SidecarConfigError, create_app
from operationproof.subject import OperationSubject
from operationproof.trust import ProviderTrustRegistry


def subject() -> OperationSubject:
    return OperationSubject(
        operation_id="op-r8",
        actor_digest=sha256_digest({"actor": "sidecar-client"}),
        intent_digest=sha256_digest({"intent": "assess"}),
        target_digest=sha256_digest({"target": "artifact"}),
        state_digest=sha256_digest({"state": "r8"}),
    )


def proof() -> dict[str, object]:
    operation_subject = subject()
    evidence = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"sidecar:{layer.value}",
            operation_id=operation_subject.operation_id,
            decision="native-pass",
            verdict=Verdict.PASS,
            subject_digest=operation_subject.digest,
            evidence_digest=sha256_digest({"evidence": layer.value}),
            issued_at="2026-08-23T20:00:00+00:00",
            metadata={"layer": layer.value},
        )
        for layer in PRE_LAYERS
    ]
    return build_pre_proof(
        operation_subject.operation_id,
        evidence,
        subject=operation_subject,
    )


def registry() -> ProviderTrustRegistry:
    result = ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        result.register(
            layer=layer,
            provider=f"sidecar:{layer.value}",
            verifier=lambda envelope, context: True,
        )
    return result


def client(
    *,
    trusted: bool = True,
    require_trust: bool = True,
    max_body_bytes: int = 1024 * 1024,
) -> TestClient:
    return TestClient(
        create_app(
            registry() if trusted else None,
            require_trust=require_trust,
            max_body_bytes=max_body_bytes,
        ),
        raise_server_exceptions=False,
    )


def test_health_is_live_without_trust_registry() -> None:
    response = client(trusted=False).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "contract": "operationproof.sidecar.v1",
        "status": "alive",
    }
    assert response.headers["cache-control"] == "no-store"


def test_readiness_fails_closed_when_trust_is_required() -> None:
    response = client(trusted=False).get("/readyz")

    assert response.status_code == 503
    assert response.json()["accepted"] is False
    assert response.json()["reason_codes"] == ["TRUST_REGISTRY_REQUIRED"]


def test_integrity_only_mode_must_be_explicit() -> None:
    response = client(trusted=False, require_trust=False).get("/readyz")

    assert response.status_code == 200
    assert response.json()["mode"] == "integrity-only"


def test_trusted_assessment_can_accept_verified_proof() -> None:
    response = client().post(
        "/v1/assess",
        content=canonical_json_bytes(proof()),
        headers={"content-type": "application/json; charset=utf-8"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["contract"] == "operationproof.sidecar.v1"
    assert payload["assessment"]["accepted"] is True
    assert payload["assessment"]["trusted"] is True


def test_provider_verifiers_do_not_run_on_event_loop() -> None:
    trusted_registry = ProviderTrustRegistry()

    def off_loop_verifier(_envelope: object, _context: object) -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return True
        return False

    for layer in PRE_LAYERS:
        trusted_registry.register(
            layer=layer,
            provider=f"sidecar:{layer.value}",
            verifier=off_loop_verifier,
        )

    response = TestClient(
        create_app(trusted_registry),
        raise_server_exceptions=False,
    ).post(
        "/v1/assess",
        content=canonical_json_bytes(proof()),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json()["assessment"]["accepted"] is True


def test_integrity_only_assessment_never_implicitly_accepts() -> None:
    response = client(trusted=False, require_trust=False).post(
        "/v1/assess",
        content=canonical_json_bytes(proof()),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    assessment = response.json()["assessment"]
    assert assessment["integrity_valid"] is True
    assert assessment["decision"] == "VERIFIED"
    assert assessment["accepted"] is False
    assert assessment["sdk_reason_codes"] == ["TRUST_NOT_EVALUATED"]


def test_assessment_is_unavailable_when_required_trust_is_missing() -> None:
    response = client(trusted=False).post(
        "/v1/assess",
        content=b"{}",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json()["reason_codes"] == ["TRUST_REGISTRY_REQUIRED"]


def test_raw_json_boundary_rejects_duplicate_keys() -> None:
    response = client().post(
        "/v1/assess",
        content=b'{"schema":"a","schema":"b"}',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["reason_codes"] == ["DUPLICATE_JSON_KEY:schema"]


def test_body_size_is_bounded_before_json_assessment() -> None:
    response = client(max_body_bytes=32).post(
        "/v1/assess",
        content=b"{" + (b"x" * 64) + b"}",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["reason_codes"] == ["REQUEST_BODY_TOO_LARGE"]


def test_content_type_and_encoding_are_narrow() -> None:
    wrong_type = client().post(
        "/v1/assess",
        content=b"{}",
        headers={"content-type": "text/plain"},
    )
    encoded = client().post(
        "/v1/assess",
        content=b"{}",
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )

    assert wrong_type.status_code == 415
    assert wrong_type.json()["reason_codes"] == ["UNSUPPORTED_MEDIA_TYPE"]
    assert encoded.status_code == 415
    assert encoded.json()["reason_codes"] == ["UNSUPPORTED_CONTENT_ENCODING"]


def test_interactive_docs_are_not_exposed() -> None:
    app_client = client()

    assert app_client.get("/docs").status_code == 404
    assert app_client.get("/openapi.json").status_code == 404


def test_invalid_runtime_config_is_rejected_before_serving() -> None:
    try:
        create_app(max_body_bytes=MAX_CONFIGURED_BODY_BYTES + 1)
    except SidecarConfigError as exc:
        assert str(exc) == "INVALID_MAX_BODY_BYTES"
    else:
        raise AssertionError("expected SidecarConfigError")
