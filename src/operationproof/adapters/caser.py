from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from ..canonical import canonical_json_bytes, sha256_digest, valid_digest
from ..domain import EvidenceEnvelope, Layer, Verdict
from ..execution import ExecutionEffect, ExecutionOutcome, build_execution_receipt
from ..rfc3339 import ParsedTimestamp, compare_timestamps, parse_rfc3339, timestamp_from_datetime
from ..verifier import verify_proof

_CASER_RECEIPT_SCHEMA = "execution-receipt/v1"
_CASER_VERIFICATION_SCHEMA = "verification-result/v1"
_BINDING_SCHEMA = "operationproof.caser-execution-binding.v1"
_INTEGRITY_ONLY_SCOPE = "EXECUTION_EVIDENCE_INTEGRITY"
_POST_STATE_SCOPE = "EXECUTION_OUTCOME_AND_PROVIDER_POST_STATE"
_POST_STATE_CLASS = "INDEPENDENT_PROVIDER_OBSERVATION"
_OUTCOME_SCOPES = {"EXECUTION_OUTCOME", _POST_STATE_SCOPE}
_SUPPORTED_VERIFICATION_STRENGTHS = {"V2", "V3"}


class CaserExecutionError(ValueError):
    """Raised when CASER execution evidence cannot be normalized safely."""


BindingVerifier = Callable[[Mapping[str, Any]], bool]


def _parse_timestamp(value: Any, code: str) -> ParsedTimestamp:
    try:
        return parse_rfc3339(value)
    except ValueError as exc:
        raise CaserExecutionError(code) from exc


def _snapshot_document(document: Mapping[str, Any], code: str) -> dict[str, Any]:
    """Deep-copy a JSON evidence document into an adapter-owned snapshot.

    Native evidence objects are caller-owned and may be mutable. The adapter must not
    consume data that can change while an external trust callback is running. A
    canonical JSON round-trip gives us a detached plain-Python snapshot and rejects
    non-JSON values fail-closed.
    """

    try:
        snapshot = json.loads(canonical_json_bytes(dict(document)).decode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise CaserExecutionError(code) from exc
    if not isinstance(snapshot, dict):
        raise CaserExecutionError(code)
    return snapshot


def _document_digest(document: Mapping[str, Any]) -> str:
    """Bind the exact canonical document supplied to this adapter.

    Native CASER contentIdentity remains a provider-owned reference. OperationProof
    additionally computes its own canonical digest so an authenticated binding cannot
    be reused after claims/checks are changed while a native identity is retained.
    """

    return sha256_digest(dict(document))


def _binding_payload(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": binding.get("schema"),
        "operation_id": binding.get("operation_id"),
        "pre_proof_digest": binding.get("pre_proof_digest"),
        "receipt_content_identity": binding.get("receipt_content_identity"),
        "verification_content_identity": binding.get("verification_content_identity"),
        "receipt_document_digest": binding.get("receipt_document_digest"),
        "verification_document_digest": binding.get("verification_document_digest"),
        "execution_instance_id": binding.get("execution_instance_id"),
        "issued_at": binding.get("issued_at"),
        "expires_at": binding.get("expires_at"),
    }


def _validated_checks(verification: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw_checks = verification.get("checks")
    if not isinstance(raw_checks, list):
        raise CaserExecutionError("INVALID_CASER_VERIFICATION_CHECKS")

    checks: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(raw_checks):
        if not isinstance(item, Mapping):
            raise CaserExecutionError(f"INVALID_CASER_VERIFICATION_CHECK_ENTRY:{index}")
        name = item.get("check")
        if not isinstance(name, str) or not name:
            raise CaserExecutionError(f"INVALID_CASER_VERIFICATION_CHECK_NAME:{index}")
        if name in checks:
            raise CaserExecutionError(f"DUPLICATE_CASER_VERIFICATION_CHECK:{name}")
        checks[name] = item
    return checks


def _require_pass_check(
    checks: Mapping[str, Mapping[str, Any]],
    name: str,
) -> Mapping[str, Any]:
    item = checks.get(name)
    if item is None or item.get("status") != "PASS":
        raise CaserExecutionError(f"CASER_REQUIRED_CHECK_NOT_PASS:{name}")
    return item


def _verified_effect(checks: Mapping[str, Mapping[str, Any]]) -> ExecutionEffect:
    read_only = checks.get("read-only-effect")
    read_only_verified = False
    if read_only is not None and read_only.get("status") == "PASS":
        if read_only.get("observed") != ExecutionEffect.READ_ONLY.value:
            raise CaserExecutionError("INVALID_VERIFIED_CASER_READ_ONLY_EFFECT")
        read_only_verified = True

    effect = checks.get("effect-class")
    effect_value: ExecutionEffect | None = None
    if effect is not None and effect.get("status") == "PASS":
        observed = effect.get("observed")
        if observed not in {item.value for item in ExecutionEffect}:
            raise CaserExecutionError("INVALID_VERIFIED_CASER_EFFECT")
        effect_value = ExecutionEffect(observed)

    if read_only_verified and effect_value not in {None, ExecutionEffect.READ_ONLY}:
        raise CaserExecutionError("CONFLICTING_CASER_EFFECT_CHECKS")
    if read_only_verified:
        return ExecutionEffect.READ_ONLY
    if effect_value is not None:
        return effect_value
    return ExecutionEffect.UNKNOWN


def _claims(verification: Mapping[str, Any]) -> tuple[bool, bool, bool]:
    claims = verification.get("claims")
    if not isinstance(claims, Mapping):
        raise CaserExecutionError("INVALID_CASER_VERIFICATION_CLAIMS")
    integrity = claims.get("receiptIntegrityVerified")
    outcome = claims.get("executionOutcomeIndependentlyVerified")
    post_state = claims.get("providerPostStateVerified")
    if not all(isinstance(value, bool) for value in (integrity, outcome, post_state)):
        raise CaserExecutionError("INVALID_CASER_VERIFICATION_CLAIM_TYPE")
    assert isinstance(integrity, bool)
    assert isinstance(outcome, bool)
    assert isinstance(post_state, bool)
    return integrity, outcome, post_state


def _validate_strength_contract(
    verification: Mapping[str, Any],
    *,
    outcome_verified: bool,
    post_state_verified: bool,
) -> None:
    """Prevent verification-strength labels from being used to escalate assurance.

    The evidenced CASER V2 contract is integrity-only. A V2 document that claims an
    independently verified execution outcome or provider post-state is contradictory
    and is rejected rather than being normalized into stronger execution evidence.
    Stronger execution claims are accepted only under the explicit V3 contract and
    remain subject to the independent scope/check/class gates below.
    """

    strength = verification.get("verificationStrength")
    scope = verification.get("verificationScope")
    if strength not in _SUPPORTED_VERIFICATION_STRENGTHS:
        raise CaserExecutionError("UNSUPPORTED_CASER_VERIFICATION_STRENGTH")
    if strength == "V2":
        if scope != _INTEGRITY_ONLY_SCOPE:
            raise CaserExecutionError("CASER_V2_OUTSIDE_INTEGRITY_ONLY_SCOPE")
        if outcome_verified or post_state_verified:
            raise CaserExecutionError("CASER_V2_CLAIM_ESCALATION")
    elif (outcome_verified or post_state_verified) and strength != "V3":
        raise CaserExecutionError("CASER_STRONG_CLAIM_REQUIRES_V3")


def _verified_outcome(
    verification: Mapping[str, Any],
    checks: Mapping[str, Mapping[str, Any]],
    *,
    outcome_verified: bool,
) -> ExecutionOutcome:
    if not outcome_verified:
        return ExecutionOutcome.UNKNOWN
    if verification.get("runnerIndependent") is not True:
        raise CaserExecutionError("CASER_OUTCOME_NOT_RUNNER_INDEPENDENT")
    scope = verification.get("verificationScope")
    if scope == _INTEGRITY_ONLY_SCOPE or scope not in _OUTCOME_SCOPES:
        raise CaserExecutionError("CASER_OUTCOME_OUTSIDE_VERIFICATION_SCOPE")

    native_outcome = verification.get("executionOutcome")
    if native_outcome not in {
        ExecutionOutcome.SUCCEEDED.value,
        ExecutionOutcome.FAILED.value,
    }:
        raise CaserExecutionError("INVALID_VERIFIED_CASER_EXECUTION_OUTCOME")

    outcome_check = _require_pass_check(checks, "execution-outcome")
    if outcome_check.get("observed") != native_outcome:
        raise CaserExecutionError("CASER_EXECUTION_OUTCOME_CHECK_MISMATCH")
    return ExecutionOutcome(native_outcome)


def _verified_post_state(
    verification: Mapping[str, Any],
    checks: Mapping[str, Mapping[str, Any]],
    *,
    post_state_verified: bool,
) -> bool:
    if not post_state_verified:
        return False
    if verification.get("runnerIndependent") is not True:
        raise CaserExecutionError("CASER_POST_STATE_NOT_RUNNER_INDEPENDENT")
    if verification.get("verificationScope") != _POST_STATE_SCOPE:
        raise CaserExecutionError("CASER_POST_STATE_OUTSIDE_VERIFICATION_SCOPE")
    if verification.get("verificationClass") != _POST_STATE_CLASS:
        raise CaserExecutionError("CASER_POST_STATE_NOT_PROVIDER_INDEPENDENT")

    check = _require_pass_check(checks, "provider-post-state")
    if check.get("observed") != "VERIFIED":
        raise CaserExecutionError("CASER_PROVIDER_POST_STATE_CHECK_MISMATCH")
    return True


class CaserExecutionAdapter:
    """Normalize CASER execution receipt + independent verification into execution evidence."""

    layer = Layer.EXECUTION
    provider_id = "caser"
    receipt_protocol = _CASER_RECEIPT_SCHEMA
    verification_protocol = _CASER_VERIFICATION_SCHEMA
    binding_protocol = _BINDING_SCHEMA

    @classmethod
    def adapt(
        cls,
        *,
        pre_proof: Mapping[str, Any],
        receipt: Mapping[str, Any],
        verification: Mapping[str, Any],
        binding: Mapping[str, Any],
        binding_verifier: BindingVerifier,
    ) -> EvidenceEnvelope:
        if not isinstance(pre_proof, dict):
            raise CaserExecutionError("INVALID_PRE_PROOF")
        pre_result = verify_proof(pre_proof)
        if not pre_result.valid:
            raise CaserExecutionError("PRE_PROOF_INTEGRITY_INVALID")
        if pre_proof.get("phase") != "PRE" or pre_proof.get("decision") != "VERIFIED":
            raise CaserExecutionError("PRE_PROOF_NOT_VERIFIED")

        operation_id = pre_proof.get("operation_id")
        pre_digest = pre_proof.get("proof_digest")
        if not isinstance(operation_id, str) or not operation_id:
            raise CaserExecutionError("INVALID_PRE_OPERATION_ID")
        if not isinstance(pre_digest, str) or not valid_digest(pre_digest):
            raise CaserExecutionError("INVALID_PRE_PROOF_DIGEST")

        if not isinstance(receipt, Mapping):
            raise CaserExecutionError("INVALID_CASER_RECEIPT")
        if not isinstance(verification, Mapping):
            raise CaserExecutionError("INVALID_CASER_VERIFICATION")
        if not isinstance(binding, Mapping):
            raise CaserExecutionError("INVALID_CASER_EXECUTION_BINDING")

        receipt = _snapshot_document(receipt, "INVALID_CASER_RECEIPT")
        verification = _snapshot_document(verification, "INVALID_CASER_VERIFICATION")
        binding = _snapshot_document(binding, "INVALID_CASER_EXECUTION_BINDING")

        if receipt.get("schemaVersion") != _CASER_RECEIPT_SCHEMA:
            raise CaserExecutionError("INVALID_CASER_RECEIPT_SCHEMA")
        if receipt.get("operationId") != operation_id:
            raise CaserExecutionError("CASER_RECEIPT_OPERATION_MISMATCH")
        execution_instance_id = receipt.get("instanceId")
        if not isinstance(execution_instance_id, str) or not execution_instance_id:
            raise CaserExecutionError("INVALID_CASER_RECEIPT_INSTANCE")
        receipt_digest = receipt.get("contentIdentity")
        if not isinstance(receipt_digest, str) or not valid_digest(receipt_digest):
            raise CaserExecutionError("INVALID_CASER_RECEIPT_CONTENT_IDENTITY")
        receipt_document_digest = _document_digest(receipt)

        if verification.get("schemaVersion") != _CASER_VERIFICATION_SCHEMA:
            raise CaserExecutionError("INVALID_CASER_VERIFICATION_SCHEMA")
        for field_name in (
            "verifierIdentity",
            "verificationStrength",
            "verificationClass",
            "verificationScope",
        ):
            value = verification.get(field_name)
            if not isinstance(value, str) or not value:
                raise CaserExecutionError(f"INVALID_CASER_VERIFICATION_FIELD:{field_name}")
        verification_digest = verification.get("contentIdentity")
        if not isinstance(verification_digest, str) or not valid_digest(verification_digest):
            raise CaserExecutionError("INVALID_CASER_VERIFICATION_CONTENT_IDENTITY")
        verification_document_digest = _document_digest(verification)
        verified_at = _parse_timestamp(
            verification.get("verifiedAt"),
            "INVALID_CASER_VERIFIED_AT",
        )

        verification_status = verification.get("status")
        if verification_status not in {"PASS", "FAIL"}:
            raise CaserExecutionError("INVALID_CASER_VERIFICATION_STATUS")

        checks = _validated_checks(verification)

        receipt_ref = verification.get("receipt")
        if not isinstance(receipt_ref, Mapping):
            raise CaserExecutionError("INVALID_CASER_VERIFICATION_RECEIPT_REF")
        if receipt_ref.get("operationId") != operation_id:
            raise CaserExecutionError("CASER_VERIFICATION_OPERATION_MISMATCH")
        if receipt_ref.get("instanceId") != execution_instance_id:
            raise CaserExecutionError("CASER_VERIFICATION_INSTANCE_MISMATCH")
        if receipt_ref.get("contentIdentity") != receipt_digest:
            raise CaserExecutionError("CASER_VERIFICATION_RECEIPT_DIGEST_MISMATCH")

        schema_check = _require_pass_check(checks, "receipt-schema")
        if schema_check.get("observed") != _CASER_RECEIPT_SCHEMA:
            raise CaserExecutionError("CASER_RECEIPT_SCHEMA_CHECK_MISMATCH")

        identity_check = _require_pass_check(checks, "content-identity")
        observed_identity = identity_check.get("observed")
        if not isinstance(observed_identity, Mapping):
            raise CaserExecutionError("INVALID_CASER_CONTENT_IDENTITY_CHECK")
        if (
            observed_identity.get("claimed") != receipt_digest
            or observed_identity.get("calculated") != receipt_digest
        ):
            raise CaserExecutionError("CASER_CONTENT_IDENTITY_CHECK_MISMATCH")

        integrity_verified, outcome_verified, post_state_claim = _claims(verification)

        if not callable(binding_verifier):
            raise CaserExecutionError("INVALID_CASER_BINDING_VERIFIER")
        if binding.get("schema") != _BINDING_SCHEMA:
            raise CaserExecutionError("INVALID_CASER_BINDING_SCHEMA")
        expected_binding = {
            "operation_id": operation_id,
            "pre_proof_digest": pre_digest,
            "receipt_content_identity": receipt_digest,
            "verification_content_identity": verification_digest,
            "receipt_document_digest": receipt_document_digest,
            "verification_document_digest": verification_document_digest,
            "execution_instance_id": execution_instance_id,
        }
        for field_name, expected in expected_binding.items():
            if binding.get(field_name) != expected:
                raise CaserExecutionError(f"CASER_BINDING_MISMATCH:{field_name}")

        issued_at = binding.get("issued_at")
        expires_at = binding.get("expires_at")
        issued = _parse_timestamp(issued_at, "INVALID_CASER_BINDING_ISSUED_AT")
        expires = _parse_timestamp(expires_at, "INVALID_CASER_BINDING_EXPIRES_AT")
        if compare_timestamps(issued, verified_at) < 0:
            raise CaserExecutionError("CASER_BINDING_PREDATES_VERIFICATION")
        if compare_timestamps(expires, issued) <= 0:
            raise CaserExecutionError("INVALID_CASER_BINDING_TIME_WINDOW")
        if compare_timestamps(expires, timestamp_from_datetime(datetime.now(UTC))) <= 0:
            raise CaserExecutionError("EXPIRED_CASER_EXECUTION_BINDING")

        binding_digest = binding.get("binding_digest")
        if not isinstance(binding_digest, str) or not valid_digest(binding_digest):
            raise CaserExecutionError("INVALID_CASER_BINDING_DIGEST")
        if binding_digest != sha256_digest(_binding_payload(binding)):
            raise CaserExecutionError("CASER_BINDING_DIGEST_MISMATCH")

        try:
            verifier_binding = _snapshot_document(binding, "INVALID_CASER_EXECUTION_BINDING")
            trusted_binding = binding_verifier(verifier_binding)
        except Exception as exc:
            raise CaserExecutionError("CASER_BINDING_VERIFICATION_ERROR") from exc
        if trusted_binding is not True:
            raise CaserExecutionError("UNTRUSTED_CASER_EXECUTION_BINDING")

        _validate_strength_contract(
            verification,
            outcome_verified=outcome_verified,
            post_state_verified=post_state_claim,
        )
        outcome = _verified_outcome(
            verification,
            checks,
            outcome_verified=outcome_verified,
        )
        post_state_verified = _verified_post_state(
            verification,
            checks,
            post_state_verified=post_state_claim,
        )
        effect = _verified_effect(checks)
        normalized = build_execution_receipt(
            provider=cls.provider_id,
            operation_id=operation_id,
            pre_proof_digest=pre_digest,
            execution_instance_id=execution_instance_id,
            effect_class=effect,
            outcome=outcome,
            native_receipt_digest=receipt_digest,
            native_verification_digest=verification_digest,
            receipt_integrity_verified=integrity_verified,
            execution_outcome_verified=outcome_verified,
            provider_post_state_verified=post_state_verified,
            issued_at=str(issued_at),
            expires_at=str(expires_at),
            metadata={
                "caser_verifier_identity": verification.get("verifierIdentity"),
                "caser_verification_strength": verification.get("verificationStrength"),
                "caser_verification_class": verification.get("verificationClass"),
                "caser_verification_scope": verification.get("verificationScope"),
                "caser_verified_at": verification.get("verifiedAt"),
                "native_receipt_document_digest": receipt_document_digest,
                "native_verification_document_digest": verification_document_digest,
            },
        )

        if verification_status == "FAIL":
            decision = "EXECUTION_VERIFICATION_FAILED"
            verdict = Verdict.FAIL
        elif not integrity_verified or not outcome_verified:
            decision = "EXECUTION_INSUFFICIENT"
            verdict = Verdict.UNKNOWN
        elif outcome == ExecutionOutcome.FAILED:
            decision = "EXECUTION_FAILED"
            verdict = Verdict.FAIL
        elif outcome != ExecutionOutcome.SUCCEEDED:
            decision = "EXECUTION_INSUFFICIENT"
            verdict = Verdict.UNKNOWN
        elif effect == ExecutionEffect.READ_ONLY or (
            effect == ExecutionEffect.MUTATING and post_state_verified
        ):
            decision = "EXECUTION_VERIFIED"
            verdict = Verdict.PASS
        else:
            decision = "EXECUTION_INSUFFICIENT"
            verdict = Verdict.UNKNOWN

        subject_digest = sha256_digest(
            {
                "execution_instance_id": execution_instance_id,
                "operation_id": operation_id,
                "pre_proof_digest": pre_digest,
            }
        )
        evidence_digest = sha256_digest(
            {
                "binding_digest": binding_digest,
                "execution_receipt_digest": normalized["receipt_digest"],
            }
        )

        return EvidenceEnvelope(
            layer=Layer.EXECUTION,
            provider=cls.provider_id,
            operation_id=operation_id,
            decision=decision,
            verdict=verdict,
            subject_digest=subject_digest,
            evidence_digest=evidence_digest,
            issued_at=str(issued_at),
            expires_at=str(expires_at),
            metadata={
                "adapter": "operationproof.caser-execution.v1",
                "binding_digest": binding_digest,
                "binding_protocol": cls.binding_protocol,
                "execution_receipt": normalized,
                "native_receipt_protocol": cls.receipt_protocol,
                "native_verification_protocol": cls.verification_protocol,
            },
        )