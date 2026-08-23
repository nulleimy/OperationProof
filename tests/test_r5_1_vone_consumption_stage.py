from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from operationproof.adapters.vone import (
    VOneAuthorizationError,
    VOneExecutionGrantAdapter,
    make_vone_execution_grant_trust_verifier,
)
from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import canonical_json_bytes, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust

_OPERATION_ID = "execution-r5-1"
_ADMISSION_NOW = datetime(2099, 1, 1, 0, 0, 30, tzinfo=UTC)
_POST_NOW = datetime(2099, 1, 1, 0, 0, 50, tzinfo=UTC)


def _native_digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _rehash(document: dict[str, Any], digest_field: str) -> None:
    payload = {key: value for key, value in document.items() if key != digest_field}
    document[digest_field] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _grant() -> dict[str, Any]:
    grant: dict[str, Any] = {
        "schema_version": 2,
        "grant_type": "execution-grant/v2",
        "grant_id": "grant_r5_1",
        "jti": "jti_r5_1",
        "execution_id": _OPERATION_ID,
        "request_id": "request_r5_1",
        "authorization_snapshot_digest": _native_digest("snapshot"),
        "snapshot_authority_witness_set_digest": _native_digest("witness-set"),
        "snapshot_authority_event_hash": _native_digest("event-hash"),
        "parent_scope_digest": _native_digest("parent-scope"),
        "authority_constraint_digest": _native_digest("authority-constraint"),
        "monotonic_authority_decision_digest": _native_digest("monotonic-decision"),
        "actor_id": "actor_r5_1",
        "workspace_id": "workspace_r5_1",
        "environment": "production",
        "capability": "deploy.release/v1",
        "capability_definition_identity": _native_digest("capability-definition"),
        "target_kind": "deployment",
        "target_digest": _native_digest("target"),
        "payload_digest": _native_digest("payload"),
        "policy_version": "policy/v1",
        "policy_identity": _native_digest("policy"),
        "approval_set_digest": _native_digest("approval-set"),
        "required_permission": "execution.run",
        "precondition_requirement_digest": _native_digest("precondition-requirement"),
        "precondition_expectation_digest": _native_digest("precondition-expectation"),
        "precondition_observation_digest": _native_digest("precondition-observation"),
        "precondition_witness_digest": _native_digest("precondition-witness"),
        "precondition_enforcement_class": "READ_THEN_COMPARE",
        "precondition_checked_at": "2099-01-01T00:00:00.000+00:00",
        "execution_binding_digest": _native_digest("execution-binding"),
        "execution_capsule_digest": _native_digest("execution-capsule"),
        "runner_class": "governed-runner/v1",
        "execution_binding_authority_revision": "binding-revision-1",
        "issued_at": "2099-01-01T00:00:10.000+00:00",
        "expires_at": "2099-01-01T00:01:10.000+00:00",
        "revocation_epoch": 7,
        "use_semantics": "ONE_TIME",
        "issuer_identity": "vone-authoritative-grant-issuer",
        "issuer_revision": "issuer-revision-1",
        "grant_digest": "",
    }
    _rehash(grant, "grant_digest")
    return grant


def _consumption(grant: dict[str, Any]) -> dict[str, Any]:
    witness: dict[str, Any] = {
        "schema_version": 1,
        "witness_type": "grant-consumption-witness/v1",
        "consumption_id": "gcon_r5_1",
        "jti": grant["jti"],
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "execution_id": grant["execution_id"],
        "authorization_snapshot_digest": grant["authorization_snapshot_digest"],
        "execution_capsule_digest": grant["execution_capsule_digest"],
        "runner_class": grant["runner_class"],
        "conformance_witness_digest": _native_digest("conformance"),
        "clock_witness_digest": _native_digest("clock"),
        "live_revocation_epoch": grant["revocation_epoch"],
        "consumed_at": "2099-01-01T00:00:40.000+00:00",
        "serialization_contract": "sqlite-begin-immediate/v1",
        "authority_revision": "durable-grant-consumption-r1",
        "witness_digest": "",
    }
    _rehash(witness, "witness_digest")
    return witness


def _authorization(grant: dict[str, Any]) -> EvidenceEnvelope:
    return VOneExecutionGrantAdapter.adapt(
        operation_id=_OPERATION_ID,
        grant=grant,
        grant_verifier=lambda _grant: True,
        now=_ADMISSION_NOW,
    )


def _pre_items(authorization: EvidenceEnvelope) -> list[EvidenceEnvelope]:
    items: list[EvidenceEnvelope] = []
    for layer in PRE_LAYERS:
        if layer == Layer.AUTHORIZATION:
            items.append(authorization)
        else:
            items.append(
                EvidenceEnvelope(
                    layer=layer,
                    provider=f"provider-{layer.value}",
                    operation_id=_OPERATION_ID,
                    decision="PASS",
                    verdict=Verdict.PASS,
                    subject_digest=sha256_digest({"subject": layer.value}),
                    evidence_digest=sha256_digest({"evidence": layer.value}),
                    issued_at="2099-01-01T00:00:00.000+00:00",
                    metadata={},
                )
            )
    return items


def _registry(
    *,
    grant: dict[str, Any],
    witness: dict[str, Any] | None,
    admission_verifier: Any,
    post_now: datetime = _POST_NOW,
) -> ProviderTrustRegistry:
    authorization = _authorization(grant)
    document_digest = str(authorization.metadata["grant_document_digest"])

    def resolve_consumption(jti: str) -> dict[str, Any] | None:
        if witness is not None and jti == grant["jti"]:
            return witness
        return None

    registry = ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        if layer == Layer.AUTHORIZATION:
            registry.register(
                layer=layer,
                provider="vone",
                verifier=make_vone_execution_grant_trust_verifier(
                    grant_resolver={document_digest: grant}.get,
                    grant_verifier=admission_verifier,
                    clock=lambda: post_now,
                    consumption_resolver=resolve_consumption,
                    consumption_verifier=lambda _witness: True,
                ),
            )
        else:
            registry.register(
                layer=layer,
                provider=f"provider-{layer.value}",
                verifier=lambda _item, _context: True,
            )
    registry.register(
        layer=Layer.EXECUTION,
        provider="execution-test",
        verifier=lambda _item, _context: True,
    )
    return registry


def _proofs(grant: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    authorization = _authorization(grant)
    pre = build_pre_proof(_OPERATION_ID, _pre_items(authorization))
    execution = EvidenceEnvelope(
        layer=Layer.EXECUTION,
        provider="execution-test",
        operation_id=_OPERATION_ID,
        decision="SUCCEEDED",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": "execution"}),
        evidence_digest=sha256_digest({"evidence": "execution"}),
        issued_at="2099-01-01T00:00:50.000+00:00",
        metadata={},
    )
    return pre, build_final_proof(pre, execution)


def test_future_issued_grant_is_rejected_before_window_begins() -> None:
    grant = _grant()
    before_issue = datetime(2099, 1, 1, 0, 0, 9, 999000, tzinfo=UTC)

    with pytest.raises(VOneAuthorizationError, match="VONE_GRANT_NOT_YET_VALID"):
        VOneExecutionGrantAdapter.adapt(
            operation_id=_OPERATION_ID,
            grant=grant,
            grant_verifier=lambda _grant: True,
            now=before_issue,
        )


def test_direct_pre_requires_live_unused_admission_even_if_consumption_exists() -> None:
    grant = _grant()
    witness = _consumption(grant)
    pre, _final = _proofs(grant)
    registry = _registry(
        grant=grant,
        witness=witness,
        admission_verifier=lambda _grant: False,
        post_now=_ADMISSION_NOW,
    )

    result = verify_proof_trust(pre, registry)

    assert result.trusted is False
    assert "UNTRUSTED_PROVIDER_EVIDENCE:authorization:vone" in result.reason_codes


def test_final_embedded_pre_uses_consumption_witness_not_unused_grant_check() -> None:
    grant = _grant()
    witness = _consumption(grant)
    _pre, final = _proofs(grant)

    def admission_must_not_run(_grant: object) -> bool:
        raise AssertionError("post-execution revalidation must not require an unused grant")

    registry = _registry(
        grant=grant,
        witness=witness,
        admission_verifier=admission_must_not_run,
    )

    result = verify_proof_trust(final, registry)

    assert result.trusted is True
    assert result.reason_codes == ()


def test_final_fails_closed_without_authoritative_consumption_witness() -> None:
    grant = _grant()
    _pre, final = _proofs(grant)
    registry = _registry(
        grant=grant,
        witness=None,
        admission_verifier=lambda _grant: True,
    )

    result = verify_proof_trust(final, registry)

    assert result.trusted is False
    assert "UNTRUSTED_PROVIDER_EVIDENCE:authorization:vone" in result.reason_codes


def test_consumption_witness_must_bind_exact_grant_and_execution() -> None:
    grant = _grant()
    witness = _consumption(grant)
    witness["execution_id"] = "different-execution"
    _rehash(witness, "witness_digest")
    _pre, final = _proofs(grant)
    registry = _registry(grant=grant, witness=witness, admission_verifier=lambda _grant: True)

    assert verify_proof_trust(final, registry).trusted is False


def test_consumption_witness_requires_same_live_revocation_epoch() -> None:
    grant = _grant()
    witness = _consumption(grant)
    witness["live_revocation_epoch"] = 8
    _rehash(witness, "witness_digest")
    _pre, final = _proofs(grant)
    registry = _registry(grant=grant, witness=witness, admission_verifier=lambda _grant: True)

    assert verify_proof_trust(final, registry).trusted is False


def test_consumption_after_grant_expiry_is_rejected() -> None:
    grant = _grant()
    witness = _consumption(grant)
    witness["consumed_at"] = grant["expires_at"]
    _rehash(witness, "witness_digest")
    _pre, final = _proofs(grant)
    registry = _registry(grant=grant, witness=witness, admission_verifier=lambda _grant: True)

    assert verify_proof_trust(final, registry).trusted is False


def test_consumption_witness_does_not_extend_grant_lifetime() -> None:
    grant = _grant()
    witness = _consumption(grant)
    _pre, final = _proofs(grant)
    registry = _registry(
        grant=grant,
        witness=witness,
        admission_verifier=lambda _grant: False,
        post_now=datetime(2099, 1, 1, 0, 5, 0, tzinfo=UTC),
    )

    assert verify_proof_trust(final, registry).trusted is False


def test_consumption_witness_tamper_fails_final_closed() -> None:
    grant = _grant()
    tampered = deepcopy(_consumption(grant))
    tampered["authority_revision"] = "tampered-without-rehash"
    authorization = _authorization(grant)
    document_digest = str(authorization.metadata["grant_document_digest"])
    verifier = make_vone_execution_grant_trust_verifier(
        grant_resolver={document_digest: grant}.get,
        grant_verifier=lambda _grant: True,
        clock=lambda: _POST_NOW,
        consumption_resolver=lambda _jti: tampered,
        consumption_verifier=lambda _witness: True,
    )
    _pre, final = _proofs(grant)
    registry = ProviderTrustRegistry()
    for item in _pre_items(authorization):
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=verifier if item.layer == Layer.AUTHORIZATION else (lambda _i, _c: True),
        )
    registry.register(
        layer=Layer.EXECUTION,
        provider="execution-test",
        verifier=lambda _i, _c: True,
    )

    assert verify_proof_trust(final, registry).trusted is False
