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
from operationproof.builder import build_pre_proof
from operationproof.canonical import canonical_json_bytes, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import (
    ProviderTrustRegistry,
    TrustVerificationContext,
    verify_proof_trust,
)

_OPERATION_ID = "execution-r5-vone"
_NOW = datetime(2030, 1, 1, 0, 0, 30, tzinfo=UTC)


def _native_digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _recompute_grant_digest(grant: dict[str, Any]) -> None:
    payload = {key: value for key, value in grant.items() if key != "grant_digest"}
    grant["grant_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _grant() -> dict[str, Any]:
    grant: dict[str, Any] = {
        "schema_version": 2,
        "grant_type": "execution-grant/v2",
        "grant_id": "grant_r5",
        "jti": "jti_r5",
        "execution_id": _OPERATION_ID,
        "request_id": "request_r5",
        "authorization_snapshot_digest": _native_digest("snapshot"),
        "snapshot_authority_witness_set_digest": _native_digest("witness-set"),
        "snapshot_authority_event_hash": _native_digest("event-hash"),
        "parent_scope_digest": _native_digest("parent-scope"),
        "authority_constraint_digest": _native_digest("authority-constraint"),
        "monotonic_authority_decision_digest": _native_digest("monotonic-decision"),
        "actor_id": "actor_r5",
        "workspace_id": "workspace_r5",
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
        "precondition_checked_at": "2030-01-01T00:00:00.000+00:00",
        "execution_binding_digest": _native_digest("execution-binding"),
        "execution_capsule_digest": _native_digest("execution-capsule"),
        "runner_class": "governed-runner/v1",
        "execution_binding_authority_revision": "binding-revision-1",
        "issued_at": "2030-01-01T00:00:10.000+00:00",
        "expires_at": "2030-01-01T00:01:10.000+00:00",
        "revocation_epoch": 7,
        "use_semantics": "ONE_TIME",
        "issuer_identity": "vone-authoritative-grant-issuer",
        "issuer_revision": "issuer-revision-1",
        "grant_digest": "",
    }
    _recompute_grant_digest(grant)
    return grant


def _adapt(grant: dict[str, Any], *, trusted: bool = True) -> EvidenceEnvelope:
    return VOneExecutionGrantAdapter.adapt(
        operation_id=_OPERATION_ID,
        grant=grant,
        grant_verifier=lambda _grant: trusted,
        now=_NOW,
    )


def test_valid_vone_grant_adapts_to_authorization_pass() -> None:
    grant = _grant()

    envelope = _adapt(grant)

    assert envelope.layer == Layer.AUTHORIZATION
    assert envelope.provider == "vone"
    assert envelope.operation_id == _OPERATION_ID
    assert envelope.decision == "execution-grant/v2"
    assert envelope.verdict == Verdict.PASS
    assert envelope.issued_at == grant["issued_at"]
    assert envelope.expires_at == grant["expires_at"]
    assert envelope.metadata["grant_digest"] == grant["grant_digest"]
    assert envelope.metadata["revocation_epoch"] == 7


def test_unknown_grant_field_fails_closed() -> None:
    grant = _grant()
    grant["self_declared_trust"] = True

    with pytest.raises(VOneAuthorizationError, match="INVALID_VONE_GRANT_FIELDS"):
        _adapt(grant)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("execution_id", "other-execution", "VONE_EXECUTION_ID_MISMATCH"),
        ("required_permission", "execution.read", "VONE_REQUIRED_PERMISSION_MISMATCH"),
        ("use_semantics", "MULTI_USE", "VONE_USE_SEMANTICS_MISMATCH"),
        ("revocation_epoch", -1, "INVALID_VONE_REVOCATION_EPOCH"),
    ],
)
def test_authority_binding_mutations_fail_closed(field: str, value: Any, code: str) -> None:
    grant = _grant()
    grant[field] = value
    _recompute_grant_digest(grant)

    with pytest.raises(VOneAuthorizationError, match=code):
        _adapt(grant)


def test_expired_grant_fails_closed() -> None:
    grant = _grant()
    now = datetime(2030, 1, 1, 0, 1, 10, tzinfo=UTC)

    with pytest.raises(VOneAuthorizationError, match="EXPIRED_VONE_GRANT"):
        VOneExecutionGrantAdapter.adapt(
            operation_id=_OPERATION_ID,
            grant=grant,
            grant_verifier=lambda _grant: True,
            now=now,
        )


def test_ttl_over_300_seconds_fails_closed() -> None:
    grant = _grant()
    grant["expires_at"] = "2030-01-01T00:05:11.000+00:00"
    _recompute_grant_digest(grant)

    with pytest.raises(VOneAuthorizationError, match="VONE_GRANT_TTL_EXCEEDED"):
        _adapt(grant)


def test_stale_precondition_to_grant_gap_fails_closed() -> None:
    grant = _grant()
    grant["precondition_checked_at"] = "2029-12-31T23:59:00.000+00:00"
    _recompute_grant_digest(grant)

    with pytest.raises(VOneAuthorizationError, match="VONE_PRECONDITION_TOO_OLD"):
        _adapt(grant)


def test_native_grant_digest_tampering_fails_closed() -> None:
    grant = _grant()
    grant["issuer_revision"] = "tampered-without-native-rehash"

    with pytest.raises(VOneAuthorizationError, match="VONE_GRANT_DIGEST_MISMATCH"):
        _adapt(grant)


def test_external_grant_verifier_false_or_exception_fails_closed() -> None:
    grant = _grant()

    with pytest.raises(VOneAuthorizationError, match="UNTRUSTED_VONE_GRANT"):
        _adapt(grant, trusted=False)

    def explode(_grant: object) -> bool:
        raise RuntimeError("authority unavailable")

    with pytest.raises(VOneAuthorizationError, match="VONE_GRANT_VERIFICATION_ERROR"):
        VOneExecutionGrantAdapter.adapt(
            operation_id=_OPERATION_ID,
            grant=grant,
            grant_verifier=explode,
            now=_NOW,
        )


def test_vone_timestamp_must_match_canonical_utc_millisecond_form() -> None:
    grant = _grant()
    grant["issued_at"] = "2030-01-01T00:00:10Z"
    _recompute_grant_digest(grant)

    with pytest.raises(VOneAuthorizationError, match="INVALID_VONE_ISSUED_AT"):
        _adapt(grant)


def test_trust_verifier_re_resolves_and_reproduces_exact_envelope() -> None:
    grant = _grant()
    envelope = _adapt(grant)
    document_digest = str(envelope.metadata["grant_document_digest"])
    authoritative = {document_digest: grant}
    verifier = make_vone_execution_grant_trust_verifier(
        grant_resolver=authoritative.get,
        grant_verifier=lambda _grant: True,
        clock=lambda: _NOW,
    )
    context = TrustVerificationContext(
        root_phase="PRE",
        evidence_phase="PRE",
        operation_id=_OPERATION_ID,
        proof_digest=sha256_digest({"proof": "r5"}),
        pre_proof_digest=None,
        evidence_index=1,
    )

    assert verifier(envelope.to_dict(), context) is True

    tampered = envelope.to_dict()
    tampered["metadata"] = dict(tampered["metadata"])
    tampered["metadata"]["issuer_revision"] = "attacker"
    assert verifier(tampered, context) is False

    final_context = TrustVerificationContext(
        root_phase="FINAL",
        evidence_phase="FINAL",
        operation_id=_OPERATION_ID,
        proof_digest=sha256_digest({"proof": "final"}),
        pre_proof_digest=sha256_digest({"pre": "digest"}),
        evidence_index=0,
    )
    assert verifier(envelope.to_dict(), final_context) is False


def test_trust_verifier_fails_if_authoritative_grant_changes() -> None:
    grant = _grant()
    envelope = _adapt(grant)
    document_digest = str(envelope.metadata["grant_document_digest"])
    changed = deepcopy(grant)
    changed["issuer_revision"] = "changed"
    _recompute_grant_digest(changed)
    verifier = make_vone_execution_grant_trust_verifier(
        grant_resolver=lambda key: changed if key == document_digest else None,
        grant_verifier=lambda _grant: True,
        clock=lambda: _NOW,
    )
    context = TrustVerificationContext(
        root_phase="PRE",
        evidence_phase="PRE",
        operation_id=_OPERATION_ID,
        proof_digest=sha256_digest({"proof": "r5-authoritative-change"}),
        pre_proof_digest=None,
        evidence_index=0,
    )

    assert verifier(envelope.to_dict(), context) is False


def _trust_all(_item: object, _context: TrustVerificationContext) -> bool:
    return True


def test_vone_adapter_integrates_with_r3_provider_trust_registry() -> None:
    grant = _grant()
    authorization = _adapt(grant)
    evidence: list[EvidenceEnvelope] = []
    for layer in PRE_LAYERS:
        if layer == Layer.AUTHORIZATION:
            evidence.append(authorization)
        else:
            evidence.append(
                EvidenceEnvelope(
                    layer=layer,
                    provider=f"provider-{layer.value}",
                    operation_id=_OPERATION_ID,
                    decision="PASS",
                    verdict=Verdict.PASS,
                    subject_digest=sha256_digest({"subject": layer.value}),
                    evidence_digest=sha256_digest({"evidence": layer.value}),
                    issued_at="2030-01-01T00:00:00.000+00:00",
                    metadata={},
                )
            )
    proof = build_pre_proof(_OPERATION_ID, evidence)

    document_digest = str(authorization.metadata["grant_document_digest"])
    registry = ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        if layer == Layer.AUTHORIZATION:
            registry.register(
                layer=layer,
                provider="vone",
                verifier=make_vone_execution_grant_trust_verifier(
                    grant_resolver={document_digest: grant}.get,
                    grant_verifier=lambda _grant: True,
                    clock=lambda: _NOW,
                ),
            )
        else:
            registry.register(
                layer=layer,
                provider=f"provider-{layer.value}",
                verifier=_trust_all,
            )

    result = verify_proof_trust(proof, registry)

    assert result.trusted is True
    assert result.reason_codes == ()
