from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from ..canonical import sha256_digest, valid_digest
from ..domain import EvidenceEnvelope, Layer, Verdict
from ..trust import TrustVerificationContext

_RECEIPT_SCHEMA = "operationproof.execution-receipt.v1"
_ALLOWED_STATUSES = {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"}


class ExecutionReceiptError(ValueError):
    """Raised when an execution receipt fails validation or trust verification."""


ReceiptVerifier = Callable[[Mapping[str, Any]], bool]
ReceiptResolver = Callable[[str], Mapping[str, Any] | None]


def _parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ExecutionReceiptError(code)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ExecutionReceiptError(code) from exc
    if parsed.tzinfo is None:
        raise ExecutionReceiptError(code)
    return parsed.astimezone(UTC)


def _receipt_payload(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": receipt.get("schema"),
        "provider": receipt.get("provider"),
        "receipt_id": receipt.get("receipt_id"),
        "operation_id": receipt.get("operation_id"),
        "pre_proof_digest": receipt.get("pre_proof_digest"),
        "status": receipt.get("status"),
        "result_digest": receipt.get("result_digest"),
        "started_at": receipt.get("started_at"),
        "completed_at": receipt.get("completed_at"),
    }


def _validate_receipt(
    *,
    receipt: Mapping[str, Any],
    expected_provider: str,
    operation_id: str,
    pre_proof_digest: str,
) -> tuple[str, str, str]:
    if receipt.get("schema") != _RECEIPT_SCHEMA:
        raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT_SCHEMA")
    if receipt.get("provider") != expected_provider:
        raise ExecutionReceiptError("EXECUTION_RECEIPT_PROVIDER_MISMATCH")

    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT_ID")
    if receipt.get("operation_id") != operation_id:
        raise ExecutionReceiptError("EXECUTION_RECEIPT_OPERATION_ID_MISMATCH")
    if receipt.get("pre_proof_digest") != pre_proof_digest:
        raise ExecutionReceiptError("EXECUTION_RECEIPT_PRE_PROOF_DIGEST_MISMATCH")

    receipt_pre_digest = receipt.get("pre_proof_digest")
    if not isinstance(receipt_pre_digest, str) or not valid_digest(receipt_pre_digest):
        raise ExecutionReceiptError("INVALID_EXECUTION_PRE_PROOF_DIGEST")

    status = receipt.get("status")
    if not isinstance(status, str) or status not in _ALLOWED_STATUSES:
        raise ExecutionReceiptError("INVALID_EXECUTION_STATUS")

    result_digest = receipt.get("result_digest")
    if not isinstance(result_digest, str) or not valid_digest(result_digest):
        raise ExecutionReceiptError("INVALID_EXECUTION_RESULT_DIGEST")

    started_at = receipt.get("started_at")
    completed_at = receipt.get("completed_at")
    started = _parse_timestamp(started_at, "INVALID_EXECUTION_STARTED_AT")
    completed = _parse_timestamp(completed_at, "INVALID_EXECUTION_COMPLETED_AT")
    if completed < started:
        raise ExecutionReceiptError("INVALID_EXECUTION_TIME_WINDOW")

    receipt_digest = receipt.get("receipt_digest")
    if not isinstance(receipt_digest, str) or not valid_digest(receipt_digest):
        raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT_DIGEST")
    if receipt_digest != sha256_digest(_receipt_payload(receipt)):
        raise ExecutionReceiptError("EXECUTION_RECEIPT_DIGEST_MISMATCH")

    return status, receipt_id, receipt_digest


def _verdict_for_status(status: str) -> Verdict:
    if status == "SUCCEEDED":
        return Verdict.PASS
    if status in {"FAILED", "CANCELLED"}:
        return Verdict.FAIL
    return Verdict.UNKNOWN


class _ExecutionReceiptAdapter:
    provider_id = ""
    receipt_protocol = _RECEIPT_SCHEMA

    @classmethod
    def adapt(
        cls,
        *,
        operation_id: str,
        pre_proof_digest: str,
        receipt: Mapping[str, Any],
        receipt_verifier: ReceiptVerifier,
    ) -> EvidenceEnvelope:
        if not isinstance(operation_id, str) or not operation_id:
            raise ExecutionReceiptError("INVALID_OPERATION_ID")
        if not isinstance(pre_proof_digest, str) or not valid_digest(pre_proof_digest):
            raise ExecutionReceiptError("INVALID_PRE_PROOF_DIGEST")
        if not isinstance(receipt, Mapping):
            raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT")
        if not callable(receipt_verifier):
            raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT_VERIFIER")
        if cls.provider_id not in {"sandcloud", "caser"}:
            raise ExecutionReceiptError("INVALID_EXECUTION_PROVIDER")

        status, receipt_id, receipt_digest = _validate_receipt(
            receipt=receipt,
            expected_provider=cls.provider_id,
            operation_id=operation_id,
            pre_proof_digest=pre_proof_digest,
        )

        try:
            trusted = receipt_verifier(receipt)
        except Exception as exc:  # fail closed across provider trust failures
            raise ExecutionReceiptError("EXECUTION_RECEIPT_VERIFICATION_ERROR") from exc
        if trusted is not True:
            raise ExecutionReceiptError("UNTRUSTED_EXECUTION_RECEIPT")

        subject_digest = sha256_digest(
            {
                "operation_id": operation_id,
                "pre_proof_digest": pre_proof_digest,
            }
        )
        evidence_digest = sha256_digest(
            {
                "provider": cls.provider_id,
                "receipt_digest": receipt_digest,
            }
        )

        return EvidenceEnvelope(
            layer=Layer.EXECUTION,
            provider=cls.provider_id,
            operation_id=operation_id,
            decision=status,
            verdict=_verdict_for_status(status),
            subject_digest=subject_digest,
            evidence_digest=evidence_digest,
            issued_at=str(receipt.get("completed_at")),
            metadata={
                "adapter": f"operationproof.{cls.provider_id}.execution.v1",
                "receipt_protocol": cls.receipt_protocol,
                "receipt_id": receipt_id,
                "receipt_digest": receipt_digest,
                "pre_proof_digest": pre_proof_digest,
            },
        )


class SandCloudExecutionReceiptAdapter(_ExecutionReceiptAdapter):
    """Adapt a trusted SandCloud receipt into execution evidence."""

    provider_id = "sandcloud"


class CaserExecutionReceiptAdapter(_ExecutionReceiptAdapter):
    """Adapt a trusted CASER receipt into execution evidence."""

    provider_id = "caser"


def make_execution_receipt_trust_verifier(
    *,
    provider_id: str,
    receipt_resolver: ReceiptResolver,
    receipt_verifier: ReceiptVerifier,
) -> Callable[[Mapping[str, Any], TrustVerificationContext], bool]:
    """Build an R3 provider-trust verifier backed by authoritative receipt lookup.

    The serialized evidence envelope is not a trust root. The resolver must return the
    exact receipt identified by its digest from trusted deployment state, and the
    verifier must authenticate that receipt out of band. The receipt is then rebound
    to the structurally verified FINAL context, especially the exact PRE proof digest.
    """

    if provider_id not in {"sandcloud", "caser"}:
        raise ExecutionReceiptError("INVALID_EXECUTION_PROVIDER")
    if not callable(receipt_resolver):
        raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT_RESOLVER")
    if not callable(receipt_verifier):
        raise ExecutionReceiptError("INVALID_EXECUTION_RECEIPT_VERIFIER")

    def verify(
        envelope: Mapping[str, Any],
        context: TrustVerificationContext,
    ) -> bool:
        try:
            if context.root_phase != "FINAL" or context.evidence_phase != "FINAL":
                return False
            if not isinstance(context.pre_proof_digest, str) or not valid_digest(
                context.pre_proof_digest
            ):
                return False
            if envelope.get("layer") != Layer.EXECUTION.value:
                return False
            if envelope.get("provider") != provider_id:
                return False
            if envelope.get("operation_id") != context.operation_id:
                return False

            metadata = envelope.get("metadata")
            if not isinstance(metadata, Mapping):
                return False
            receipt_digest = metadata.get("receipt_digest")
            if not isinstance(receipt_digest, str) or not valid_digest(receipt_digest):
                return False

            receipt = receipt_resolver(receipt_digest)
            if not isinstance(receipt, Mapping):
                return False
            status, receipt_id, validated_digest = _validate_receipt(
                receipt=receipt,
                expected_provider=provider_id,
                operation_id=context.operation_id,
                pre_proof_digest=context.pre_proof_digest,
            )
            if validated_digest != receipt_digest:
                return False
            if metadata.get("receipt_id") != receipt_id:
                return False
            if metadata.get("pre_proof_digest") != context.pre_proof_digest:
                return False
            if envelope.get("decision") != status:
                return False
            if envelope.get("verdict") != _verdict_for_status(status).value:
                return False

            expected_subject_digest = sha256_digest(
                {
                    "operation_id": context.operation_id,
                    "pre_proof_digest": context.pre_proof_digest,
                }
            )
            if envelope.get("subject_digest") != expected_subject_digest:
                return False
            expected_evidence_digest = sha256_digest(
                {"provider": provider_id, "receipt_digest": receipt_digest}
            )
            if envelope.get("evidence_digest") != expected_evidence_digest:
                return False

            return receipt_verifier(receipt) is True
        except Exception:  # noqa: BLE001 - trust boundary must fail closed
            return False

    return verify
