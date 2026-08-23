from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from operationproof.adapters.caser import _parse_timestamp as parse_caser_timestamp
from operationproof.canonical import sha256_digest
from operationproof.domain import EvidenceEnvelope, Layer, ProofDecision, Verdict
from operationproof.execution import execution_receipt_payload, verify_execution_receipt
from operationproof.rfc3339 import (
    compare_timestamps,
    parse_rfc3339,
    timestamp_from_datetime,
)
from operationproof.verifier import evaluate_evidence_set


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


def _execution_envelope(*, issued_at: str, expires_at: str) -> dict[str, object]:
    return EvidenceEnvelope(
        layer=Layer.EXECUTION,
        provider="caser",
        operation_id="op-r4-1-envelope",
        decision="EXECUTION_VERIFIED",
        verdict=Verdict.PASS,
        subject_digest=sha256_digest({"subject": "r4.1"}),
        evidence_digest=sha256_digest({"evidence": "r4.1"}),
        issued_at=issued_at,
        expires_at=expires_at,
        metadata={"adapter": "regression"},
    ).to_dict()


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


def test_known_leap_second_remains_before_following_minute() -> None:
    leap = parse_rfc3339("2016-12-31T23:59:60.9Z")
    following = parse_rfc3339("2017-01-01T00:00:00.5Z")

    assert compare_timestamps(leap, following) < 0


def test_known_leap_second_with_offset_maps_to_same_instant() -> None:
    utc = parse_rfc3339("2016-12-31T23:59:60.25Z")
    offset = parse_rfc3339("2017-01-01T00:59:60.2500+01:00")

    assert compare_timestamps(utc, offset) == 0


@pytest.mark.parametrize(
    "value",
    [
        "2026-08-23T12:34:60Z",
        "2016-12-31T12:34:60Z",
        "2017-01-01T00:00:60Z",
    ],
)
def test_second_60_outside_known_leap_position_fails_closed(value: str) -> None:
    with pytest.raises(ValueError, match="known UTC leap second"):
        parse_rfc3339(value)


def test_unicode_digits_are_rejected() -> None:
    with pytest.raises(ValueError, match="syntax"):
        parse_rfc3339("٢٠٢٦-٠٨-٢٣T٠٠:٠٠:٠٠Z")


def test_unicode_fraction_digits_are_rejected() -> None:
    with pytest.raises(ValueError, match="syntax"):
        parse_rfc3339("2026-08-23T00:00:00.١Z")


def test_unknown_negative_zero_offset_is_not_treated_as_exact_utc() -> None:
    with pytest.raises(ValueError, match="unknown local offset"):
        parse_rfc3339("2026-08-23T00:00:00-00:00")


@pytest.mark.parametrize(
    "value",
    [
        "0001-01-01T00:00:00+00:01",
        "9999-12-31T23:59:59-00:01",
    ],
)
def test_utc_normalization_overflow_becomes_validation_failure(value: str) -> None:
    with pytest.raises(ValueError, match="UTC-normalized"):
        parse_rfc3339(value)


def test_datetime_and_rfc3339_share_post_leap_time_scale() -> None:
    text = parse_rfc3339("2026-08-23T00:00:00.123456Z")
    native = timestamp_from_datetime(datetime(2026, 8, 23, 0, 0, 0, 123456, tzinfo=UTC))

    assert compare_timestamps(text, native) == 0


def test_execution_receipt_rejects_expiry_inside_leap_second_before_next_minute_issue() -> None:
    receipt = _receipt(
        issued_at="2017-01-01T00:00:00.5Z",
        expires_at="2016-12-31T23:59:60.9Z",
    )

    result = verify_execution_receipt(
        receipt,
        now=datetime(2016, 12, 31, 23, 59, 59, tzinfo=UTC),
    )

    assert result.valid is False
    assert "INVALID_EXECUTION_RECEIPT_EXPIRY_ORDER" in result.reason_codes


def test_evidence_verifier_accepts_exact_submicrosecond_window() -> None:
    envelope = _execution_envelope(
        issued_at="2026-08-23T00:00:00.0000001Z",
        expires_at="2026-08-23T00:00:00.0000009Z",
    )

    decision, reasons = evaluate_evidence_set(
        operation_id="op-r4-1-envelope",
        evidence=[envelope],
        required_layers={Layer.EXECUTION.value},
        allowed_layers={Layer.EXECUTION.value},
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    assert decision == ProofDecision.VERIFIED
    assert reasons == []


def test_evidence_verifier_accepts_leap_second_to_following_minute_window() -> None:
    envelope = _execution_envelope(
        issued_at="2016-12-31T23:59:60.9Z",
        expires_at="2017-01-01T00:00:00.5Z",
    )

    decision, reasons = evaluate_evidence_set(
        operation_id="op-r4-1-envelope",
        evidence=[envelope],
        required_layers={Layer.EXECUTION.value},
        allowed_layers={Layer.EXECUTION.value},
        now=datetime(2016, 12, 31, 23, 59, 59, tzinfo=UTC),
    )

    assert decision == ProofDecision.VERIFIED
    assert reasons == []


def test_execution_receipt_invalid_now_overflow_fails_closed() -> None:
    receipt = _receipt(
        issued_at="2026-08-23T00:00:00Z",
        expires_at=None,
    )
    invalid_now = datetime(
        1,
        1,
        1,
        tzinfo=timezone(timedelta(minutes=1)),
    )

    result = verify_execution_receipt(receipt, now=invalid_now)

    assert result.valid is False
    assert "INVALID_EXECUTION_RECEIPT_NOW" in result.reason_codes


def test_evidence_verifier_invalid_now_overflow_fails_closed() -> None:
    envelope = _execution_envelope(
        issued_at="2026-08-23T00:00:00Z",
        expires_at="2026-08-23T00:00:01Z",
    )
    invalid_now = datetime(
        1,
        1,
        1,
        tzinfo=timezone(timedelta(minutes=1)),
    )

    decision, reasons = evaluate_evidence_set(
        operation_id="op-r4-1-envelope",
        evidence=[envelope],
        required_layers={Layer.EXECUTION.value},
        allowed_layers={Layer.EXECUTION.value},
        now=invalid_now,
    )

    assert decision == ProofDecision.REJECTED
    assert reasons == ["INVALID_VERIFICATION_NOW"]
