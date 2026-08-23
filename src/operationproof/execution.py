from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .canonical import sha256_digest, valid_digest
from .rfc3339 import ParsedTimestamp, compare_timestamps, parse_rfc3339, timestamp_from_datetime

_EXECUTION_RECEIPT_SCHEMA = "operationproof.execution-receipt.v1"


class ExecutionEffect(StrEnum):
    READ_ONLY = "READ_ONLY"
    MUTATING = "MUTATING"
    UNKNOWN = "UNKNOWN"


class ExecutionOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ExecutionReceiptVerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]


def _parse_time(value: Any) -> ParsedTimestamp:
    return parse_rfc3339(value)


def execution_receipt_payload(receipt: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(receipt)
    payload.pop("receipt_digest", None)
    return payload


def build_execution_receipt(
    *,
    provider: str,
    operation_id: str,
    pre_proof_digest: str,
    execution_instance_id: str,
    effect_class: ExecutionEffect | str,
    outcome: ExecutionOutcome | str,
    native_receipt_digest: str,
    native_verification_digest: str,
    receipt_integrity_verified: bool,
    execution_outcome_verified: bool,
    provider_post_state_verified: bool,
    issued_at: str,
    expires_at: str | None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    effect_value = effect_class.value if isinstance(effect_class, ExecutionEffect) else effect_class
    outcome_value = outcome.value if isinstance(outcome, ExecutionOutcome) else outcome
    receipt: dict[str, Any] = {
        "schema": _EXECUTION_RECEIPT_SCHEMA,
        "provider": provider,
        "operation_id": operation_id,
        "pre_proof_digest": pre_proof_digest,
        "execution_instance_id": execution_instance_id,
        "effect_class": effect_value,
        "outcome": outcome_value,
        "native_receipt_digest": native_receipt_digest,
        "native_verification_digest": native_verification_digest,
        "receipt_integrity_verified": receipt_integrity_verified,
        "execution_outcome_verified": execution_outcome_verified,
        "provider_post_state_verified": provider_post_state_verified,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "metadata": dict(metadata or {}),
    }
    result = verify_execution_receipt(
        {**receipt, "receipt_digest": sha256_digest(receipt)},
    )
    if not result.valid:
        raise ValueError("INVALID_EXECUTION_RECEIPT:" + ",".join(result.reason_codes))
    receipt["receipt_digest"] = sha256_digest(receipt)
    return receipt


def verify_execution_receipt(
    receipt: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> ExecutionReceiptVerificationResult:
    reasons: list[str] = []
    now = now or datetime.now(UTC)
    try:
        now_timestamp = timestamp_from_datetime(now)
    except ValueError:
        now_timestamp = timestamp_from_datetime(datetime.now(UTC))
        reasons.append("INVALID_EXECUTION_RECEIPT_NOW")

    if receipt.get("schema") != _EXECUTION_RECEIPT_SCHEMA:
        reasons.append("UNSUPPORTED_EXECUTION_RECEIPT_SCHEMA")

    for field_name in ("provider", "operation_id", "execution_instance_id"):
        value = receipt.get(field_name)
        if not isinstance(value, str) or not value:
            reasons.append(f"INVALID_EXECUTION_RECEIPT_FIELD:{field_name}")

    for field_name in (
        "pre_proof_digest",
        "native_receipt_digest",
        "native_verification_digest",
        "receipt_digest",
    ):
        value = receipt.get(field_name)
        if not isinstance(value, str) or not valid_digest(value):
            reasons.append(f"INVALID_EXECUTION_RECEIPT_DIGEST:{field_name}")

    if receipt.get("effect_class") not in {item.value for item in ExecutionEffect}:
        reasons.append("INVALID_EXECUTION_EFFECT")
    if receipt.get("outcome") not in {item.value for item in ExecutionOutcome}:
        reasons.append("INVALID_EXECUTION_OUTCOME")

    for field_name in (
        "receipt_integrity_verified",
        "execution_outcome_verified",
        "provider_post_state_verified",
    ):
        if not isinstance(receipt.get(field_name), bool):
            reasons.append(f"INVALID_EXECUTION_RECEIPT_BOOLEAN:{field_name}")

    issued: ParsedTimestamp | None = None
    try:
        issued = _parse_time(receipt.get("issued_at"))
    except (TypeError, ValueError):
        reasons.append("INVALID_EXECUTION_RECEIPT_ISSUED_AT")

    expires_at = receipt.get("expires_at")
    if expires_at is not None:
        try:
            expires = _parse_time(expires_at)
            if compare_timestamps(expires, now_timestamp) <= 0:
                reasons.append("EXPIRED_EXECUTION_RECEIPT")
            if issued is not None and compare_timestamps(expires, issued) <= 0:
                reasons.append("INVALID_EXECUTION_RECEIPT_EXPIRY_ORDER")
        except (TypeError, ValueError):
            reasons.append("INVALID_EXECUTION_RECEIPT_EXPIRES_AT")

    if not isinstance(receipt.get("metadata"), Mapping):
        reasons.append("INVALID_EXECUTION_RECEIPT_METADATA")

    if (
        receipt.get("outcome") in {ExecutionOutcome.SUCCEEDED.value, ExecutionOutcome.FAILED.value}
        and receipt.get("execution_outcome_verified") is not True
    ):
        reasons.append("UNVERIFIED_EXECUTION_OUTCOME_CLAIM")

    supplied_digest = receipt.get("receipt_digest")
    if (
        isinstance(supplied_digest, str)
        and valid_digest(supplied_digest)
        and sha256_digest(execution_receipt_payload(receipt)) != supplied_digest
    ):
        reasons.append("EXECUTION_RECEIPT_DIGEST_MISMATCH")

    return ExecutionReceiptVerificationResult(
        valid=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )
