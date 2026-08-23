from __future__ import annotations

from copy import deepcopy

from operationproof.builder import build_pre_proof
from operationproof.canonical import proof_payload, sha256_digest
from operationproof.domain import PRE_LAYERS, EvidenceEnvelope, Verdict
from operationproof.verifier import evaluate_pre_semantics, verify_proof


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
    assert "DECISION_MISMATCH" in result.reason_codes
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
