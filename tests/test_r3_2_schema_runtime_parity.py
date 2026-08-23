from __future__ import annotations

from copy import deepcopy

from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import proof_payload, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Layer, Verdict
from operationproof.verifier import evaluate_final_semantics, evaluate_pre_semantics, verify_proof


def _pre_proof() -> dict[str, object]:
    operation_id = "op-r3-2-schema-parity"
    evidence = [
        EvidenceEnvelope(
            layer=layer,
            provider=f"provider-{layer.value}",
            operation_id=operation_id,
            decision="ALLOW",
            verdict=Verdict.PASS,
            subject_digest=sha256_digest({"subject": layer.value}),
            evidence_digest=sha256_digest({"evidence": layer.value}),
            issued_at="2026-08-23T00:00:00Z",
            metadata={"source": "r3.2-regression"},
        )
        for layer in PRE_LAYERS
    ]
    return build_pre_proof(operation_id, evidence)


def _execution() -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=Layer.EXECUTION,
        provider="provider-execution",
        operation_id="op-r3-2-schema-parity",
        decision="EXECUTION_VERIFIED",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": "execution"}),
        evidence_digest=sha256_digest({"evidence": "execution"}),
        issued_at="2026-08-23T00:00:01Z",
        metadata={"source": "r3.2-regression"},
    )


def _recompute_proof_digest(proof: dict[str, object]) -> None:
    proof["proof_digest"] = sha256_digest(proof_payload(proof))


def test_valid_pre_proof_remains_valid() -> None:
    proof = _pre_proof()
    result = verify_proof(proof)
    assert result.valid is True
    assert result.reason_codes == ()


def test_unknown_proof_field_fails_even_after_digest_recomputation() -> None:
    proof = _pre_proof()
    proof["smuggled_authority"] = {"granted": True}
    _recompute_proof_digest(proof)
    result = verify_proof(proof)
    assert result.valid is False
    assert "UNEXPECTED_PROOF_FIELDS:smuggled_authority" in result.reason_codes
    assert "PROOF_DIGEST_MISMATCH" not in result.reason_codes


def test_unknown_evidence_field_fails_even_after_proof_digest_recomputation() -> None:
    proof = _pre_proof()
    evidence = deepcopy(proof["evidence"])
    assert isinstance(evidence, list)
    first = evidence[0]
    assert isinstance(first, dict)
    first["unsigned_extension"] = "attacker-controlled"
    proof["evidence"] = evidence
    _recompute_proof_digest(proof)

    decision, reasons = evaluate_pre_semantics(str(proof["operation_id"]), evidence)
    result = verify_proof(proof)

    assert decision.value == "REJECTED"
    assert any(reason.startswith("UNEXPECTED_EVIDENCE_FIELDS:") for reason in reasons)
    assert result.valid is False
    assert any(
        reason.startswith("UNEXPECTED_EVIDENCE_FIELDS:") for reason in result.reason_codes
    )
    assert "PROOF_DIGEST_MISMATCH" not in result.reason_codes


def test_self_consistent_rejected_proof_cannot_launder_unknown_evidence_field() -> None:
    proof = _pre_proof()
    evidence = deepcopy(proof["evidence"])
    assert isinstance(evidence, list)
    first = evidence[0]
    assert isinstance(first, dict)
    first["unsigned_extension"] = {"looks": "documented"}
    proof["evidence"] = evidence

    decision, reasons = evaluate_pre_semantics(str(proof["operation_id"]), evidence)
    assert decision.value == "REJECTED"
    proof["decision"] = decision.value
    proof["reason_codes"] = reasons
    _recompute_proof_digest(proof)

    result = verify_proof(proof)

    assert result.valid is False
    assert any(
        reason.startswith("UNEXPECTED_EVIDENCE_FIELDS:") for reason in result.reason_codes
    )
    assert "DECISION_MISMATCH" not in result.reason_codes
    assert "REASON_CODES_MISMATCH" not in result.reason_codes
    assert "PROOF_DIGEST_MISMATCH" not in result.reason_codes


def test_metadata_remains_open_as_declared_by_schema() -> None:
    proof = _pre_proof()
    evidence = deepcopy(proof["evidence"])
    assert isinstance(evidence, list)
    first = evidence[0]
    assert isinstance(first, dict)
    metadata = first["metadata"]
    assert isinstance(metadata, dict)
    metadata["provider_specific_detail"] = {"nested": [1, 2, 3]}
    proof["evidence"] = evidence
    _recompute_proof_digest(proof)
    result = verify_proof(proof)
    assert result.valid is True


def test_nested_pre_proof_unknown_field_is_rejected_recursively() -> None:
    pre = _pre_proof()
    tampered_pre = deepcopy(pre)
    tampered_pre["hidden_field"] = "not-in-schema"
    _recompute_proof_digest(tampered_pre)
    pre_result = verify_proof(tampered_pre)
    assert pre_result.valid is False
    assert "UNEXPECTED_PROOF_FIELDS:hidden_field" in pre_result.reason_codes


def test_final_cannot_launder_self_consistent_nested_pre_integrity_failure() -> None:
    pre = _pre_proof()
    final = build_final_proof(pre, _execution())

    nested_pre = deepcopy(pre)
    nested_evidence = deepcopy(nested_pre["evidence"])
    assert isinstance(nested_evidence, list)
    first = nested_evidence[0]
    assert isinstance(first, dict)
    first["unsigned_extension"] = "nested-smuggle"
    nested_pre["evidence"] = nested_evidence

    nested_decision, nested_reasons = evaluate_pre_semantics(
        str(nested_pre["operation_id"]),
        nested_evidence,
    )
    nested_pre["decision"] = nested_decision.value
    nested_pre["reason_codes"] = nested_reasons
    _recompute_proof_digest(nested_pre)

    final["pre_proof"] = nested_pre
    final["pre_proof_digest"] = nested_pre["proof_digest"]
    final_decision, final_reasons = evaluate_final_semantics(
        operation_id=final["operation_id"],
        pre_proof=nested_pre,
        pre_digest=nested_pre["proof_digest"],
        evidence=final["evidence"],
    )
    final["decision"] = final_decision.value
    final["reason_codes"] = final_reasons
    _recompute_proof_digest(final)

    result = verify_proof(final)

    assert nested_decision.value == "REJECTED"
    assert final_decision.value == "REJECTED"
    assert result.valid is False
    assert "PRE_PROOF_INTEGRITY_INVALID" in result.reason_codes
    assert any(
        reason.startswith("PRE_PROOF_INTEGRITY:UNEXPECTED_EVIDENCE_FIELDS:")
        for reason in result.reason_codes
    )
    assert "DECISION_MISMATCH" not in result.reason_codes
    assert "REASON_CODES_MISMATCH" not in result.reason_codes
    assert "PROOF_DIGEST_MISMATCH" not in result.reason_codes
