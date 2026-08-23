from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .canonical import sha256_digest
from .domain import EvidenceEnvelope
from .subject import OperationSubject
from .verifier import evaluate_final_semantics, evaluate_pre_semantics


def _finalize(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["proof_digest"] = sha256_digest(result)
    return result


def build_pre_proof(
    operation_id: str,
    evidence: Iterable[EvidenceEnvelope],
    *,
    subject: OperationSubject | None = None,
) -> dict[str, Any]:
    envelopes = [item.to_dict() for item in evidence]
    subject_digest: str | None = None
    if subject is not None:
        if not isinstance(subject, OperationSubject):
            raise TypeError("INVALID_OPERATION_SUBJECT")
        if subject.operation_id != operation_id:
            raise ValueError("SUBJECT_OPERATION_ID_MISMATCH")
        subject_digest = subject.digest

    decision, reasons = evaluate_pre_semantics(
        operation_id,
        envelopes,
        expected_subject_digest=subject_digest,
    )
    payload: dict[str, Any] = {
        "schema": (
            "operationproof.operation-proof.v2"
            if subject is not None
            else "operationproof.operation-proof.v1"
        ),
        "phase": "PRE",
        "operation_id": operation_id,
        "decision": decision.value,
        "reason_codes": reasons,
        "evidence": sorted(envelopes, key=lambda item: item["layer"]),
    }
    if subject is not None:
        payload["subject"] = subject.to_dict()
        payload["subject_digest"] = subject_digest
    return _finalize(payload)


def build_final_proof(
    pre_proof: dict[str, Any],
    execution: EvidenceEnvelope,
) -> dict[str, Any]:
    operation_id = pre_proof.get("operation_id")
    evidence = [execution.to_dict()]
    pre_digest = pre_proof.get("proof_digest")
    subject_digest = (
        pre_proof.get("subject_digest")
        if pre_proof.get("schema") == "operationproof.operation-proof.v2"
        else None
    )
    decision, reasons = evaluate_final_semantics(
        operation_id=operation_id,
        pre_proof=pre_proof,
        pre_digest=pre_digest,
        evidence=evidence,
        expected_subject_digest=(
            subject_digest if isinstance(subject_digest, str) else None
        ),
    )
    payload: dict[str, Any] = {
        "schema": pre_proof.get("schema", "operationproof.operation-proof.v1"),
        "phase": "FINAL",
        "operation_id": operation_id,
        "decision": decision.value,
        "reason_codes": reasons,
        "pre_proof_digest": pre_digest,
        "pre_proof": pre_proof,
        "evidence": evidence,
    }
    if pre_proof.get("schema") == "operationproof.operation-proof.v2":
        payload["subject"] = pre_proof.get("subject")
        payload["subject_digest"] = subject_digest
    return _finalize(payload)
