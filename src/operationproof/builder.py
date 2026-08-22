from __future__ import annotations

from typing import Any, Iterable

from .canonical import sha256_digest
from .domain import EvidenceEnvelope
from .verifier import evaluate_final_semantics, evaluate_pre_semantics


def _finalize(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["proof_digest"] = sha256_digest(result)
    return result


def build_pre_proof(
    operation_id: str,
    evidence: Iterable[EvidenceEnvelope],
) -> dict[str, Any]:
    envelopes = [item.to_dict() for item in evidence]
    decision, reasons = evaluate_pre_semantics(operation_id, envelopes)
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
    operation_id = pre_proof.get("operation_id")
    evidence = [execution.to_dict()]
    pre_digest = pre_proof.get("proof_digest")
    decision, reasons = evaluate_final_semantics(
        operation_id=operation_id,
        pre_proof=pre_proof,
        pre_digest=pre_digest,
        evidence=evidence,
    )
    payload: dict[str, Any] = {
        "schema": "operationproof.operation-proof.v1",
        "phase": "FINAL",
        "operation_id": operation_id,
        "decision": decision.value,
        "reason_codes": reasons,
        "pre_proof_digest": pre_digest,
        "pre_proof": pre_proof,
        "evidence": evidence,
    }
    return _finalize(payload)
