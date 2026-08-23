from __future__ import annotations

import json

import operationproof

from operationproof.builder import build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Verdict
from operationproof.sdk import (
    SDK_CONTRACT,
    ProofDocumentError,
    assess_proof,
    assess_proof_json,
    canonical_proof_json,
    parse_proof_json,
)
from operationproof.subject import OperationSubject
from operationproof.trust import ProviderTrustRegistry


def subject() -> OperationSubject:
    return OperationSubject(
        operation_id="op-r7",
        actor_digest=sha256_digest({"actor": "sdk-user"}),
        intent_digest=sha256_digest({"intent": "verify"}),
        target_digest=sha256_digest({"target": "artifact"}),
        state_digest=sha256_digest({"state": "revision-1"}),
    )


def proof(*, unknown_layer: str | None = None) -> dict[str, object]:
    operation_subject = subject()
    evidence = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"sdk:{layer.value}",
            operation_id=operation_subject.operation_id,
            decision="native-ok",
            verdict=Verdict.UNKNOWN if layer.value == unknown_layer else Verdict.PASS,
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


def registry(*, mutate: bool = False) -> ProviderTrustRegistry:
    result = ProviderTrustRegistry()

    for layer in PRE_LAYERS:
        def verifier(envelope: object, context: object, *, mutate_item: bool = mutate) -> bool:
            if not isinstance(envelope, dict):
                return False
            if mutate_item:
                metadata = envelope.get("metadata")
                if isinstance(metadata, dict):
                    metadata["mutated_by_verifier"] = True
            return True

        result.register(
            layer=layer,
            provider=f"sdk:{layer.value}",
            verifier=verifier,
        )
    return result


def test_sdk_contract_is_named_and_public_surface_is_pinned() -> None:
    assert SDK_CONTRACT == "operationproof.sdk.v1"
    assert operationproof.__all__ == [
        "EvidenceEnvelope",
        "ExecutionEffect",
        "ExecutionOutcome",
        "ExecutionReceiptVerificationResult",
        "Layer",
        "OperationSubject",
        "OperationSubjectError",
        "ProofAssessment",
        "ProofDecision",
        "ProofDocumentError",
        "ProviderTrustRegistry",
        "SDK_CONTRACT",
        "SubjectBindingError",
        "TrustVerificationContext",
        "TrustVerificationResult",
        "Verdict",
        "VerificationResult",
        "assess_proof",
        "assess_proof_json",
        "bind_evidence_to_subject",
        "build_execution_receipt",
        "build_final_proof",
        "build_pre_proof",
        "canonical_proof_json",
        "make_subject_bound_trust_verifier",
        "parse_proof_json",
        "verify_execution_receipt",
        "verify_proof",
        "verify_proof_trust",
    ]


def test_verified_integrity_without_trust_is_never_accepted() -> None:
    assessment = assess_proof(proof())

    assert assessment.integrity_valid is True
    assert assessment.decision == "VERIFIED"
    assert assessment.trust_evaluated is False
    assert assessment.trusted is None
    assert assessment.accepted is False
    assert assessment.sdk_reason_codes == ("TRUST_NOT_EVALUATED",)
    assert "SDK:TRUST_NOT_EVALUATED" in assessment.reason_codes


def test_verified_and_trusted_proof_is_accepted() -> None:
    assessment = assess_proof(proof(), registry=registry())

    assert assessment.integrity_valid is True
    assert assessment.decision == "VERIFIED"
    assert assessment.trust_evaluated is True
    assert assessment.trusted is True
    assert assessment.accepted is True
    assert assessment.reason_codes == ()


def test_semantically_rejected_proof_is_never_accepted() -> None:
    assessment = assess_proof(proof(unknown_layer="intent"), registry=registry())

    assert assessment.integrity_valid is True
    assert assessment.decision == "REJECTED"
    assert assessment.trusted is False
    assert assessment.accepted is False
    assert "TRUST:PROOF_NOT_VERIFIED" in assessment.reason_codes


def test_invalid_registry_fails_closed_without_raising() -> None:
    assessment = assess_proof(proof(), registry=object())  # type: ignore[arg-type]

    assert assessment.integrity_valid is True
    assert assessment.trust_evaluated is False
    assert assessment.accepted is False
    assert assessment.sdk_reason_codes == ("INVALID_TRUST_REGISTRY",)


def test_assessment_detaches_provider_callbacks_from_caller_owned_proof() -> None:
    caller_proof = proof()
    before = json.loads(canonical_proof_json(caller_proof))

    assessment = assess_proof(caller_proof, registry=registry(mutate=True))

    assert assessment.accepted is True
    assert caller_proof == before


def test_strict_parser_rejects_duplicate_keys() -> None:
    raw = '{"schema":"operationproof.operation-proof.v1","schema":"other"}'

    assessment = assess_proof_json(raw)

    assert assessment.integrity_valid is False
    assert assessment.accepted is False
    assert assessment.sdk_reason_codes == ("DUPLICATE_JSON_KEY:schema",)


def test_strict_parser_rejects_non_finite_json_numbers() -> None:
    assessment = assess_proof_json('{"value":NaN}')

    assert assessment.integrity_valid is False
    assert assessment.sdk_reason_codes == ("NON_FINITE_JSON_NUMBER:NaN",)


def test_parse_proof_json_requires_top_level_object() -> None:
    try:
        parse_proof_json("[]")
    except ProofDocumentError as exc:
        assert str(exc) == "PROOF_DOCUMENT_MUST_BE_OBJECT"
    else:
        raise AssertionError("expected ProofDocumentError")


def test_canonical_proof_json_is_deterministic_and_round_trips() -> None:
    original = proof()
    canonical = canonical_proof_json(original)
    parsed = parse_proof_json(canonical)

    assert canonical == canonical_proof_json(parsed)
    assert parsed == original
