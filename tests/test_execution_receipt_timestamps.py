from __future__ import annotations

from typing import Any

import pytest

from operationproof.adapters.execution import ExecutionReceiptError, SandCloudExecutionReceiptAdapter
from operationproof.canonical import sha256_digest


def _receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": receipt["schema"],
        "provider": receipt["provider"],
        "receipt_id": receipt["receipt_id"],
        "operation_id": receipt["operation_id"],
        "pre_proof_digest": receipt["pre_proof_digest"],
        "status": receipt["status"],
        "result_digest": receipt["result_digest"],
        "started_at": receipt["started_at"],
        "completed_at": receipt["completed_at"],
    }


def _receipt(*, pre_proof_digest: str) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema": "operationproof.execution-receipt.v1",
        "provider": "sandcloud",
        "receipt_id": "sandcloud-receipt-rfc3339",
        "operation_id": "op-rfc3339",
        "pre_proof_digest": pre_proof_digest,
        "status": "SUCCEEDED",
        "result_digest": sha256_digest({"result": "ok"}),
        "started_at": "2026-08-23T00:00:00Z",
        "completed_at": "2026-08-23T00:00:01Z",
    }
    receipt["receipt_digest"] = sha256_digest(_receipt_payload(receipt))
    return receipt


def _adapt(receipt: dict[str, Any], pre_proof_digest: str) -> None:
    SandCloudExecutionReceiptAdapter.adapt(
        operation_id="op-rfc3339",
        pre_proof_digest=pre_proof_digest,
        receipt=receipt,
        receipt_verifier=lambda item: True,
    )


def test_valid_rfc3339_z_timestamps_are_accepted() -> None:
    pre_proof_digest = sha256_digest({"pre": "rfc3339"})
    receipt = _receipt(pre_proof_digest=pre_proof_digest)

    _adapt(receipt, pre_proof_digest)


def test_valid_rfc3339_offset_timestamps_are_accepted() -> None:
    pre_proof_digest = sha256_digest({"pre": "offset"})
    receipt = _receipt(pre_proof_digest=pre_proof_digest)
    receipt["started_at"] = "2026-08-23T01:00:00+01:00"
    receipt["completed_at"] = "2026-08-23T01:00:01+01:00"
    receipt["receipt_digest"] = sha256_digest(_receipt_payload(receipt))

    _adapt(receipt, pre_proof_digest)


@pytest.mark.parametrize(
    ("field", "value", "error_code"),
    [
        ("started_at", "20260823T000000+0000", "INVALID_EXECUTION_STARTED_AT"),
        ("completed_at", "20260823T000001+0000", "INVALID_EXECUTION_COMPLETED_AT"),
        ("started_at", "2026-08-23 00:00:00+00:00", "INVALID_EXECUTION_STARTED_AT"),
        ("completed_at", "2026-08-23T00:00:01+0000", "INVALID_EXECUTION_COMPLETED_AT"),
    ],
)
def test_non_rfc3339_iso8601_timestamp_forms_fail_closed(
    field: str,
    value: str,
    error_code: str,
) -> None:
    pre_proof_digest = sha256_digest({"pre": field, "value": value})
    receipt = _receipt(pre_proof_digest=pre_proof_digest)
    receipt[field] = value
    receipt["receipt_digest"] = sha256_digest(_receipt_payload(receipt))

    with pytest.raises(ExecutionReceiptError, match=error_code):
        _adapt(receipt, pre_proof_digest)
