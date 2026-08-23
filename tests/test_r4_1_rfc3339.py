from __future__ import annotations

from datetime import UTC, datetime

from operationproof.adapters.caser import _parse_timestamp as parse_caser_timestamp
from operationproof.canonical import sha256_digest
from operationproof.execution import execution_receipt_payload, verify_execution_receipt
from operationproof.rfc3339 import compare_timestamps, parse_rfc3339


def _receipt(*, issued_at: str, expires_at: str | None) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "operationproof.execution-receipt.v1",
        "provider": "caser",
        "operation_id": "op-r4-1",
        "pre_proof_digest": sha256_digest({"pre": "r4.1"}),
        "execution_instance_id": "instance-r4-1",
        "effect_class": "UNKNOWN",
        "outcome": "UNKNOWN",
        "native_receipt_digest": sha256_digest({"native": "receipt"}),
        "native_verification_digest": sha256_digest({"native": "verification"}),
        "receipt_integrity_verified": True,
        "execution_outcome_verified": False,
        "provider_post_state_verified": False,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "metadata": {},
    }
    receipt["receipt_digest"] = sha256_digest(execution_receipt_payload(receipt))
    return receipt


def test_lowercase_rfc3339_designators_are_schema_compatible() -> None:
    lower = parse_rfc3339("2026-08-23t00:00:00.123z")
    upper = parse_rfc3339("2026-08-23T00:00:00.123Z")

    assert compare_timestamps(lower, upper) == 0
    assert parse_caser_timestamp("2026-08-23t00:00:00z", "BAD") == parse_rfc3339(
        "2026-08-23T00:00:00Z"
    )


def test_arbitrary_fractional_precision_is_not_rounded() -> None:
    earlier = parse_rfc3339(
        "2026-08-23T00:00:00.0000000000000000000000000000000000000001Z"
    )
    later = parse_rfc3339(
        "2026-08-23T00:00:00.0000000000000000000000000000000000000009Z"
    )

    assert compare_timestamps(earlier, later) < 0
    assert compare_timestamps(later, earlier) > 0


def test_execution_receipt_accepts_lowercase_rfc3339() -> None:
    receipt = _receipt(
        issued_at="2026-08-23t00:00:00z",
        expires_at="2026-08-23t00:00:02z",
    )

    result = verify_execution_receipt(
        receipt,
        now=datetime(2026, 8, 23, 0, 0, 1, tzinfo=UTC),
    )

    assert result.valid is True
    assert result.reason_codes == ()


def test_execution_receipt_rejects_non_rfc3339_compact_form() -> None:
    receipt = _receipt(
        issued_at="20260823T000000+0000",
        expires_at=None,
    )

    result = verify_execution_receipt(
        receipt,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert result.valid is False
    assert "INVALID_EXECUTION_RECEIPT_ISSUED_AT" in result.reason_codes


def test_execution_receipt_rejects_submicrosecond_reversed_expiry() -> None:
    receipt = _receipt(
        issued_at="2026-08-23T00:00:00.0000009Z",
        expires_at="2026-08-23T00:00:00.0000001Z",
    )

    result = verify_execution_receipt(
        receipt,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert result.valid is False
    assert "INVALID_EXECUTION_RECEIPT_EXPIRY_ORDER" in result.reason_codes


def test_offset_equivalent_instants_compare_equal() -> None:
    utc = parse_rfc3339("2026-08-23T00:00:00.25Z")
    offset = parse_rfc3339("2026-08-23T01:00:00.2500+01:00")

    assert compare_timestamps(utc, offset) == 0
