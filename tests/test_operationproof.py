from operationproof.builder import build_final_proof, build_pre_proof
from operationproof.canonical import sha256_digest
from operationproof.domain import EvidenceEnvelope, Layer, PRE_LAYERS, Verdict
from operationproof.verifier import verify_proof


def evidence(
    layer: Layer,
    verdict: Verdict = Verdict.PASS,
    operation_id: str = "op-1",
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        layer=layer,
        provider=f"test:{layer.value}",
        operation_id=operation_id,
        decision="native-ok",
        verdict=verdict,
        subject_digest=sha256_digest({"subject": layer.value}),
        evidence_digest=sha256_digest({"evidence": layer.value, "verdict": verdict.value}),
        issued_at="2026-08-22T00:00:00+00:00",
    )


def test_pre_proof_verified_with_all_seven_pre_layers() -> None:
    proof = build_pre_proof("op-1", [evidence(layer) for layer in PRE_LAYERS])
    assert proof["decision"] == "VERIFIED"
    assert verify_proof(proof).valid is True


def test_rejected_pre_proof_can_still_be_integrity_valid() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS]
    items[2] = evidence(Layer.INTENT, Verdict.UNKNOWN)
    proof = build_pre_proof("op-1", items)
    assert proof["decision"] == "REJECTED"
    assert "LAYER_UNKNOWN:intent" in proof["reason_codes"]
    assert verify_proof(proof).valid is True


def test_missing_layer_is_rejected() -> None:
    proof = build_pre_proof("op-1", [evidence(layer) for layer in PRE_LAYERS[:-1]])
    assert proof["decision"] == "REJECTED"
    assert "MISSING_LAYER:resource" in proof["reason_codes"]
    assert verify_proof(proof).valid is True


def test_execution_cannot_appear_in_pre_proof() -> None:
    items = [evidence(layer) for layer in PRE_LAYERS] + [evidence(Layer.EXECUTION)]
    proof = build_pre_proof("op-1", items)
    assert proof["decision"] == "REJECTED"
    assert "FORBIDDEN_LAYER:execution" in proof["reason_codes"]


def test_final_proof_binds_verified_pre_proof_and_execution() -> None:
    pre = build_pre_proof("op-1", [evidence(layer) for layer in PRE_LAYERS])
    final = build_final_proof(pre, evidence(Layer.EXECUTION))
    assert final["decision"] == "VERIFIED"
    assert final["pre_proof_digest"] == pre["proof_digest"]
    assert final["pre_proof"] == pre
    assert verify_proof(final).valid is True


def test_final_rejects_execution_for_another_operation() -> None:
    pre = build_pre_proof("op-1", [evidence(layer) for layer in PRE_LAYERS])
    final = build_final_proof(pre, evidence(Layer.EXECUTION, operation_id="op-2"))
    assert final["decision"] == "REJECTED"
    assert "OPERATION_ID_MISMATCH:execution" in final["reason_codes"]
    assert verify_proof(final).valid is True


def test_tampered_proof_digest_is_detected() -> None:
    proof = build_pre_proof("op-1", [evidence(layer) for layer in PRE_LAYERS])
    proof["operation_id"] = "tampered"
    result = verify_proof(proof)
    assert result.valid is False
    assert "PROOF_DIGEST_MISMATCH" in result.reason_codes


def test_tampered_embedded_pre_proof_is_detected() -> None:
    pre = build_pre_proof("op-1", [evidence(layer) for layer in PRE_LAYERS])
    final = build_final_proof(pre, evidence(Layer.EXECUTION))
    final["pre_proof"]["operation_id"] = "tampered"
    result = verify_proof(final)
    assert result.valid is False
    assert "PROOF_DIGEST_MISMATCH" in result.reason_codes
