from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from operationproof.adapters.caser import CaserExecutionAdapter
from operationproof.adapters.howedo import HowedoWitnessAdapter
from operationproof.adapters.vone import (
    VOneExecutionGrantAdapter,
    make_vone_execution_grant_trust_verifier,
)
from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import canonical_json_bytes, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.subject import OperationSubject
from operationproof.subject_binding import (
    bind_evidence_to_subject,
    make_subject_bound_trust_verifier,
)
from operationproof.trust import ProviderTrustRegistry, verify_proof_trust
from operationproof.verifier import verify_proof

_OPERATION_ID = "execution-r6-first-party"
_NOW = datetime(2030, 1, 1, 0, 0, 30, tzinfo=UTC)


def _subject() -> OperationSubject:
    return OperationSubject(
        operation_id=_OPERATION_ID,
        actor_digest=sha256_digest({"actor": "vone:actor-r6"}),
        intent_digest=sha256_digest({"intent": "deploy.release/v1", "payload": "artifact-r6"}),
        target_digest=sha256_digest({"target": "deployment-r6"}),
        state_digest=sha256_digest({"state": "revision-r6"}),
    )


def _subject_binding(
    envelope: EvidenceEnvelope,
    subject: OperationSubject,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "operationproof.subject-binding.v1",
        "operation_id": envelope.operation_id,
        "layer": envelope.layer.value,
        "provider": envelope.provider,
        "native_envelope_digest": sha256_digest(envelope.to_dict()),
        "native_subject_digest": envelope.subject_digest,
        "canonical_subject_digest": subject.digest,
        "issued_at": "2030-01-01T00:00:25+00:00",
        "expires_at": "2030-01-01T00:01:00+00:00",
    }
    return {**payload, "binding_digest": sha256_digest(payload)}


def _bind(envelope: EvidenceEnvelope, subject: OperationSubject) -> tuple[EvidenceEnvelope, dict[str, object]]:
    binding = _subject_binding(envelope, subject)
    bound = bind_evidence_to_subject(
        envelope,
        subject=subject,
        binding=binding,
        binding_verifier=lambda candidate: candidate.get("binding_digest") == binding["binding_digest"],
        now=_NOW,
    )
    return bound, binding


def _howedo_native() -> EvidenceEnvelope:
    snapshot_id = sha256_digest({"snapshot": "r6"})
    reason_codes: tuple[str, ...] = ()
    witness_digest = sha256_digest(
        {
            "action": "CONTINUE",
            "reason_codes": reason_codes,
            "snapshot_id": snapshot_id,
        }
    )
    witness = {
        "snapshot_id": snapshot_id,
        "action": "CONTINUE",
        "reason_codes": [],
        "witness_digest": witness_digest,
    }
    binding_payload = {
        "schema": "operationproof.howedo-binding.v1",
        "operation_id": _OPERATION_ID,
        "snapshot_id": snapshot_id,
        "witness_digest": witness_digest,
        "issued_at": "2030-01-01T00:00:10+00:00",
        "expires_at": "2030-01-01T00:01:10+00:00",
    }
    binding = {
        **binding_payload,
        "binding_digest": sha256_digest(binding_payload),
    }
    return HowedoWitnessAdapter.adapt(
        operation_id=_OPERATION_ID,
        witness=witness,
        binding=binding,
        binding_verifier=lambda candidate: candidate.get("binding_digest") == binding["binding_digest"],
    )


def _native_digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _vone_grant() -> dict[str, Any]:
    grant: dict[str, Any] = {
        "schema_version": 2,
        "grant_type": "execution-grant/v2",
        "grant_id": "grant_r6",
        "jti": "jti_r6",
        "execution_id": _OPERATION_ID,
        "request_id": "request_r6",
        "authorization_snapshot_digest": _native_digest("snapshot-r6"),
        "snapshot_authority_witness_set_digest": _native_digest("witness-set-r6"),
        "snapshot_authority_event_hash": _native_digest("event-hash-r6"),
        "parent_scope_digest": _native_digest("parent-scope-r6"),
        "authority_constraint_digest": _native_digest("authority-constraint-r6"),
        "monotonic_authority_decision_digest": _native_digest("monotonic-decision-r6"),
        "actor_id": "actor_r6",
        "workspace_id": "workspace_r6",
        "environment": "production",
        "capability": "deploy.release/v1",
        "capability_definition_identity": _native_digest("capability-definition-r6"),
        "target_kind": "deployment",
        "target_digest": _native_digest("target-r6"),
        "payload_digest": _native_digest("payload-r6"),
        "policy_version": "policy/v1",
        "policy_identity": _native_digest("policy-r6"),
        "approval_set_digest": _native_digest("approval-set-r6"),
        "required_permission": "execution.run",
        "precondition_requirement_digest": _native_digest("precondition-requirement-r6"),
        "precondition_expectation_digest": _native_digest("precondition-expectation-r6"),
        "precondition_observation_digest": _native_digest("precondition-observation-r6"),
        "precondition_witness_digest": _native_digest("precondition-witness-r6"),
        "precondition_enforcement_class": "READ_THEN_COMPARE",
        "precondition_checked_at": "2030-01-01T00:00:00.000+00:00",
        "execution_binding_digest": _native_digest("execution-binding-r6"),
        "execution_capsule_digest": _native_digest("execution-capsule-r6"),
        "runner_class": "governed-runner/v1",
        "execution_binding_authority_revision": "binding-revision-r6",
        "issued_at": "2030-01-01T00:00:10.000+00:00",
        "expires_at": "2030-01-01T00:01:10.000+00:00",
        "revocation_epoch": 7,
        "use_semantics": "ONE_TIME",
        "issuer_identity": "vone-authoritative-grant-issuer",
        "issuer_revision": "issuer-revision-r6",
        "grant_digest": "",
    }
    payload = {key: value for key, value in grant.items() if key != "grant_digest"}
    grant["grant_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return grant


def _canonical_pre(subject: OperationSubject) -> tuple[dict[str, object], list[EvidenceEnvelope]]:
    items = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"r6-pre:{layer.value}",
            operation_id=_OPERATION_ID,
            decision="PASS",
            verdict=Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"r6-pre": layer.value}),
            issued_at="2026-08-23T00:00:00+00:00",
        )
        for layer in PRE_LAYERS
    ]
    return build_pre_proof(_OPERATION_ID, items, subject=subject), items


def _caser_execution(pre: dict[str, object]) -> EvidenceEnvelope:
    receipt = {
        "schemaVersion": "execution-receipt/v1",
        "operationId": _OPERATION_ID,
        "instanceId": "receipt-r6",
        "contentIdentity": sha256_digest({"native": "receipt-r6"}),
    }
    verification: dict[str, object] = {
        "schemaVersion": "verification-result/v1",
        "instanceId": "verification-r6",
        "verifierIdentity": "caser-independent-verifier/v0.1",
        "verifiedAt": "2030-01-01T00:00:20+00:00",
        "verificationStrength": "V3",
        "verificationClass": "INDEPENDENT_CODE_PATH",
        "verificationScope": "EXECUTION_OUTCOME",
        "receipt": {
            "contentIdentity": receipt["contentIdentity"],
            "operationId": receipt["operationId"],
            "instanceId": receipt["instanceId"],
        },
        "runnerIndependent": True,
        "checks": [
            {"check": "receipt-schema", "status": "PASS", "observed": "execution-receipt/v1"},
            {
                "check": "content-identity",
                "status": "PASS",
                "observed": {
                    "claimed": receipt["contentIdentity"],
                    "calculated": receipt["contentIdentity"],
                },
            },
            {"check": "read-only-effect", "status": "PASS", "observed": "READ_ONLY"},
            {"check": "execution-outcome", "status": "PASS", "observed": "SUCCEEDED"},
        ],
        "status": "PASS",
        "claims": {
            "receiptIntegrityVerified": True,
            "executionOutcomeIndependentlyVerified": True,
            "providerPostStateVerified": False,
        },
        "executionOutcome": "SUCCEEDED",
        "contentIdentity": sha256_digest({"native": "verification-r6"}),
    }
    binding_payload = {
        "schema": "operationproof.caser-execution-binding.v1",
        "operation_id": _OPERATION_ID,
        "pre_proof_digest": pre["proof_digest"],
        "receipt_content_identity": receipt["contentIdentity"],
        "verification_content_identity": verification["contentIdentity"],
        "receipt_document_digest": sha256_digest(receipt),
        "verification_document_digest": sha256_digest(verification),
        "execution_instance_id": receipt["instanceId"],
        "issued_at": "2030-01-01T00:00:25+00:00",
        "expires_at": "2030-01-01T00:01:00+00:00",
    }
    binding = {
        **binding_payload,
        "binding_digest": sha256_digest(binding_payload),
        "attestation": "r6-test-binding",
    }
    return CaserExecutionAdapter.adapt(
        pre_proof=pre,
        receipt=receipt,
        verification=verification,
        binding=binding,
        binding_verifier=lambda candidate: candidate.get("attestation") == "r6-test-binding",
    )


def test_howedo_output_can_be_trustedly_correlated_to_canonical_subject() -> None:
    subject = _subject()
    native = _howedo_native()
    bound, binding = _bind(native, subject)

    assert native.subject_digest != subject.digest
    assert bound.subject_digest == subject.digest
    marker = bound.metadata["operationproof_subject_binding"]
    assert marker["native_subject_digest"] == native.subject_digest
    assert marker["binding_digest"] == binding["binding_digest"]


def test_vone_native_trust_survives_canonical_subject_bridge() -> None:
    subject = _subject()
    grant = _vone_grant()
    native = VOneExecutionGrantAdapter.adapt(
        operation_id=_OPERATION_ID,
        grant=grant,
        grant_verifier=lambda candidate: True,
        now=_NOW,
    )
    bound, binding = _bind(native, subject)

    pre_items = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"r6-pre:{layer.value}",
            operation_id=_OPERATION_ID,
            decision="PASS",
            verdict=Verdict.PASS,
            subject_digest=subject.digest,
            evidence_digest=sha256_digest({"r6-pre": layer.value}),
            issued_at="2026-08-23T00:00:00+00:00",
        )
        for layer in PRE_LAYERS
        if layer is not Layer.AUTHORIZATION
    ]
    pre_items.append(bound)
    pre = build_pre_proof(_OPERATION_ID, pre_items, subject=subject)

    native_verifier = make_vone_execution_grant_trust_verifier(
        grant_resolver=lambda digest: (
            grant if digest == native.metadata["grant_document_digest"] else None
        ),
        grant_verifier=lambda candidate: True,
        clock=lambda: _NOW,
    )
    subject_verifier = make_subject_bound_trust_verifier(
        native_verifier=native_verifier,
        binding_resolver=lambda digest: (
            binding if digest == binding["binding_digest"] else None
        ),
        binding_verifier=lambda candidate: candidate.get("binding_digest") == binding["binding_digest"],
        clock=lambda: _NOW,
    )

    registry = ProviderTrustRegistry()
    for item in pre_items:
        if item.layer is Layer.AUTHORIZATION:
            registry.register(layer=item.layer, provider=item.provider, verifier=subject_verifier)
        else:
            registry.register(
                layer=item.layer,
                provider=item.provider,
                verifier=lambda envelope, context: True,
            )

    assert pre["decision"] == "VERIFIED"
    assert verify_proof(pre).valid is True
    assert verify_proof_trust(pre, registry).trusted is True


def test_caser_execution_can_bind_exact_v2_pre_and_canonical_subject() -> None:
    subject = _subject()
    pre, pre_items = _canonical_pre(subject)
    native_execution = _caser_execution(pre)
    execution, subject_binding = _bind(native_execution, subject)
    final = build_final_proof(pre, execution)

    expected_native = native_execution.to_dict()

    def caser_native_verifier(envelope: object, context: object) -> bool:
        if envelope != expected_native:
            return False
        metadata = expected_native["metadata"]
        if not isinstance(metadata, dict):
            return False
        normalized = metadata.get("execution_receipt")
        return (
            isinstance(normalized, dict)
            and getattr(context, "root_phase", None) == "FINAL"
            and getattr(context, "pre_proof_digest", None) == pre["proof_digest"]
            and normalized.get("pre_proof_digest") == pre["proof_digest"]
        )

    subject_verifier = make_subject_bound_trust_verifier(
        native_verifier=caser_native_verifier,
        binding_resolver=lambda digest: (
            subject_binding if digest == subject_binding["binding_digest"] else None
        ),
        binding_verifier=lambda candidate: (
            candidate.get("binding_digest") == subject_binding["binding_digest"]
        ),
        clock=lambda: _NOW,
    )

    registry = ProviderTrustRegistry()
    for item in pre_items:
        registry.register(
            layer=item.layer,
            provider=item.provider,
            verifier=lambda envelope, context: True,
        )
    registry.register(
        layer=Layer.EXECUTION,
        provider=native_execution.provider,
        verifier=subject_verifier,
    )

    assert native_execution.subject_digest != subject.digest
    assert execution.subject_digest == subject.digest
    assert final["decision"] == "VERIFIED"
    assert verify_proof(final).valid is True
    assert verify_proof_trust(final, registry).trusted is True
