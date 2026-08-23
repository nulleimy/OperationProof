from operationproof.adapters.execution import (
    ExecutionReceiptError,
    SandCloudExecutionReceiptAdapter,
)
from operationproof.canonical import sha256_digest


def _receipt(pre_proof_digest: str) -> dict[str, str]:
    receipt = {
        "schema": "operationproof.execution-receipt.v1",
        "provider": "sandcloud",
        "receipt_id": "sandcloud-receipt-extra-field",
        "operation_id": "op-r4-fields",
        "pre_proof_digest": pre_proof_digest,
        "status": "SUCCEEDED",
        "result_digest": sha256_digest({"result": "ok"}),
        "started_at": "2026-08-23T00:00:00+00:00",
        "completed_at": "2026-08-23T00:00:01+00:00",
    }
    receipt["receipt_digest"] = sha256_digest(receipt)
    return receipt


def test_extra_receipt_field_is_rejected_even_when_base_digest_is_valid() -> None:
    pre_digest = sha256_digest({"pre": "exact"})
    receipt = _receipt(pre_digest)
    receipt["unsigned_extension"] = "attacker-controlled"

    try:
        SandCloudExecutionReceiptAdapter.adapt(
            operation_id="op-r4-fields",
            pre_proof_digest=pre_digest,
            receipt=receipt,
            receipt_verifier=lambda item: True,
        )
    except ExecutionReceiptError as exc:
        assert str(exc) == "INVALID_EXECUTION_RECEIPT_FIELDS"
    else:
        raise AssertionError("unknown receipt fields must fail closed")
