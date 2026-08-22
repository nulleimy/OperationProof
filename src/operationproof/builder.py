from __future__ import annotations

from typing import Any, Iterable

from .canonical import sha256_digest
from .domain import EvidenceEnvelope, Layer, PRE_LAYERS, ProofDecision, Verdict
from .verifier import evaluate_evidence_set, verify_proof


def _finalize(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["proof_digest"] = sha256_digest(result)
    return result


def build_pre_proof(
    operation_id: str,
    evidence: Iterable[EvidenceEnvelope],
) -> dict[str, Any]:
    envelopes = [item.to_dict() for item in evidence]
    decision, reasons = evaluate_evidence_set(
        operation_id=operation_id,
        evidence=envelopes,
        required_layers={layer.value for layer in PRE_LAYERS},
        forbidden_layers={Layer.EXECUTION.value},
    )
    payload: dict[str, Any] = {
        "schema": "operationproof.operation-proof.v1",
        "phase": "PRE",
        "operation_id": operation_id,
        "decision": decision.value,
        "reason_codes": reasons,
        "evidence": sorted(envelopes, key=lambda item: item["layer"]),
    }
    return _finalize(payload)


def build_final_proof(
    pre_proof: dict[str, Any],
    execution: EvidenceEnvelope,
) -> dict[str, Any]:
    pre_result = verify_proof(pre_proof)
    reasons: list[str] = []

    if not pre_result.valid:
        reasons.append("PRE_PROOF_INVALID")
    if pre_proof.get("phase") != "PRE":
        reasons.append("PRE_PROOF_PHASE_INVALID")
    if pre_proof.get("decision") != ProofDecision.VERIFIED.value:
        reasons.append("PRE_PROOF_NOT_VERIFIED")
    if execution.layer is not Layer.EXECUTION:
        reasons.append("EXECUTION_LAYER_REQUIRED")
    if execution.operation_id != pre_proof.get("operation_id"):
        reasons.append("EXECUTION_OPERATION_ID_MISMATCH")
    if execution.verdict is Verdict.FAIL:
        reasons.append("EXECUTION_FAIL")
    elif execution.verdict is Verdict.UNKNOWN:
        reasons.append("EXECUTION_UNKNOWN")

    decision = ProofDecision.VERIFIED if not reasons else ProofDecision.REJECTED
    payload: dict[str, Any] = {
        "schema": "operationproof.operation-proof.v1",
        "phase": "FINAL",
        "operation_id": pre_proof.get("operation_id"),
        "decision": decision.value,
        "reason_codes": sorted(set(reasons)),
        "pre_proof_digest": pre_proof.get("proof_digest"),
        "evidence": [execution.to_dict()],
    }
    return _finalize(payload)
