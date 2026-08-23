from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from operationproof.adapters.vone import (
    VOneExecutionGrantAdapter,
    make_vone_execution_grant_trust_verifier,
)
from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import canonical_json_bytes, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust

_OPERATION_ID = "execution-r5-1-snapshot"
_NOW = datetime(2099, 1, 1, 0, 0, 50, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _rehash(document: dict[str, Any], digest_field: str) -> None:
    payload = {key: value for key, value in document.items() if key != digest_field}
    document[digest_field] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _grant() -> dict[str, Any]:
    grant: dict[str, Any] = {
        "schema_version": 2,
        "grant_type": "execution-grant/v2",
        "grant_id": "grant_snapshot",
        "jti": "jti_snapshot",
        "execution_id": _OPERATION_ID,
        "request_id": "request_snapshot",
        "authorization_snapshot_digest": _digest("snapshot"),
        "snapshot_authority_witness_set_digest": _digest("witness-set"),
        "snapshot_authority_event_hash": _digest("event-hash"),
        "parent_scope_digest": _digest("parent-scope"),
        "authority_constraint_digest": _digest("authority-constraint"),
        "monotonic_authority_decision_digest": _digest("monotonic-decision"),
        "actor_id": "actor_snapshot",
        "workspace_id": "workspace_snapshot",
        "environment": "production",
        "capability": "deploy.release/v1",
        "capability_definition_identity": _digest("capability-definition"),
        "target_kind": "deployment",
        "target_digest": _digest("target"),
        "payload_digest": _digest("payload"),
        "policy_version": "policy/v1",
        "policy_identity": _digest("policy"),
        "approval_set_digest": _digest("approval-set"),
        "required_permission": "execution.run",
        "precondition_requirement_digest": _digest("precondition-requirement"),
        "precondition_expectation_digest": _digest("precondition-expectation"),
        "precondition_observation_digest": _digest("precondition-observation"),
        "precondition_witness_digest": _digest("precondition-witness"),
        "precondition_enforcement_class": "READ_THEN_COMPARE",
        "precondition_checked_at": "2099-01-01T00:00:00.000+00:00",
        "execution_binding_digest": _digest("execution-binding"),
        "execution_capsule_digest": _digest("execution-capsule"),
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


def _witness(grant: dict[str, Any]) -> dict[str, Any]:
    witness: dict[str, Any] = {
        "schema_version": 1,
        "witness_type": "grant-consumption-witness/v1",
        "consumption_id": "gcon_snapshot",
        "jti": grant["jti"],
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "execution_id": grant["execution_id"],
        "authorization_snapshot_digest": grant["authorization_snapshot_digest"],
        "execution_capsule_digest": grant["execution_capsule_digest"],
        "runner_class": grant["runner_class"],
        "conformance_witness_digest": _digest("conformance"),
        "clock_witness_digest": _digest("clock"),
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
        now=_NOW,
    )


def _proofs(grant: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    authorization = _authorization(grant)
    pre_items: list[EvidenceEnvelope] = []
    for layer in PRE_LAYERS:
        if layer == Layer.AUTHORIZATION:
            pre_items.append(authorization)
        else:
            pre_items.append(
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
    pre = build_pre_proof(_OPERATION_ID, pre_items)
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


def _registry(
    *,
    grant: dict[str, Any],
    witness: dict[str, Any] | None,
    grant_verifier: Any,
    consumption_verifier: Any = None,
) -> ProviderTrustRegistry:
    authorization = _authorization(grant)
    document_digest = str(authorization.metadata["grant_document_digest"])
    vone_verifier = make_vone_execution_grant_trust_verifier(
        grant_resolver={document_digest: grant}.get,
        grant_verifier=grant_verifier,
        clock=lambda: _NOW,
        consumption_resolver=(
            lambda jti: witness if witness is not None and jti == grant["jti"] else None
        ),
        consumption_verifier=(
            consumption_verifier
            if consumption_verifier is not None
            else (lambda _witness: True)
        ),
    )

    registry = ProviderTrustRegistry()
    for layer in PRE_LAYERS:
        if layer == Layer.AUTHORIZATION:
            registry.register(layer=layer, provider="vone", verifier=vone_verifier)
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


def test_direct_trust_grant_verifier_mutation_is_detached() -> None:
    grant = _grant()
    pre, _final = _proofs(grant)

    def mutate_candidate(candidate: dict[str, Any]) -> bool:
        candidate["actor_id"] = "attacker"
        candidate["payload_digest"] = _digest("attacker-payload")
        return True

    registry = _registry(
        grant=grant,
        witness=None,
        grant_verifier=mutate_candidate,
    )

    assert verify_proof_trust(pre, registry).trusted is True
    assert grant["actor_id"] == "actor_snapshot"
    assert grant["payload_digest"] == _digest("payload")


def test_embedded_consumption_verifier_mutation_is_detached() -> None:
    grant = _grant()
    witness = _witness(grant)
    _pre, final = _proofs(grant)

    def admission_must_not_run(_grant: object) -> bool:
        raise AssertionError("embedded PRE must use consumption authority")

    def mutate_candidate(candidate: dict[str, Any]) -> bool:
        candidate["execution_id"] = "attacker-execution"
        candidate["authority_revision"] = "attacker-revision"
        return True

    registry = _registry(
        grant=grant,
        witness=witness,
        grant_verifier=admission_must_not_run,
        consumption_verifier=mutate_candidate,
    )

    assert verify_proof_trust(final, registry).trusted is True
    assert witness["execution_id"] == _OPERATION_ID
    assert witness["authority_revision"] == "durable-grant-consumption-r1"
