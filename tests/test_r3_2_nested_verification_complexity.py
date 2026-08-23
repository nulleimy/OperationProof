from __future__ import annotations

from typing import Any

import operationproof.verifier as verifier_module
from operationproof.canonical import proof_payload, sha256_digest


def _digest_proof(proof: dict[str, Any]) -> dict[str, Any]:
    proof["proof_digest"] = sha256_digest(proof_payload(proof))
    return proof


def _nested_final_chain(depth: int) -> dict[str, Any]:
    operation_id = "op-r3-2-linear-recursion"
    current: dict[str, Any] = _digest_proof(
        {
            "schema": "operationproof.operation-proof.v1",
            "phase": "PRE",
            "operation_id": operation_id,
            "decision": "REJECTED",
            "reason_codes": [],
            "evidence": [],
        }
    )
    for _ in range(depth):
        current = _digest_proof(
            {
                "schema": "operationproof.operation-proof.v1",
                "phase": "FINAL",
                "operation_id": operation_id,
                "decision": "REJECTED",
                "reason_codes": [],
                "pre_proof_digest": current["proof_digest"],
                "pre_proof": current,
                "evidence": [],
            }
        )
    return current


def test_nested_final_verification_grows_linearly(monkeypatch: Any) -> None:
    depth = 18
    proof = _nested_final_chain(depth)
    original = verifier_module.verify_proof
    calls = 0

    def counting_verify(candidate: dict[str, Any]):
        nonlocal calls
        calls += 1
        return original(candidate)

    monkeypatch.setattr(verifier_module, "verify_proof", counting_verify)

    result = counting_verify(proof)

    assert result.valid is False
    assert calls == depth + 1
