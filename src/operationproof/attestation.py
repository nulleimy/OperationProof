from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .canonical import canonical_json_bytes, sha256_digest, valid_digest
from .rfc3339 import compare_timestamps, parse_rfc3339, timestamp_from_datetime

ATTESTATION_CONTRACT = "operationproof.attestation.v1"
SIGNED_ATTESTATION_CONTRACT = "operationproof.signed-attestation.v1"
SIGNATURE_CONTRACT = "operationproof.attestation-signature.v1"
GENESIS = "GENESIS"
HMAC_SHA256_V1 = "hmac-sha256.v1"
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{16,2048}$")
_ATTESTATION_FIELDS = frozenset(
    {
        "schema",
        "attestation_id",
        "operation_id",
        "subject_digest",
        "proof_digest",
        "artifact_type",
        "artifact_digest",
        "issuer_id",
        "issued_at",
        "sequence",
        "previous_attestation_digest",
        "payload_digest",
        "attestation_digest",
    }
)
_SIGNED_ATTESTATION_FIELDS = frozenset({"schema", "attestation", "signature"})
_SIGNATURE_FIELDS = frozenset(
    {
        "schema",
        "algorithm",
        "issuer_id",
        "key_id",
        "attestation_digest",
        "signature",
    }
)


@dataclass(frozen=True, slots=True)
class AttestationVerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]
    attestation_digest: str | None = None


@dataclass(frozen=True, slots=True)
class SignatureVerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]
    integrity_valid: bool
    signature_valid: bool
    issuer_id: str | None = None
    algorithm: str | None = None
    key_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProvenanceVerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]
    attestation_count: int
    operation_id: str | None = None
    subject_digest: str | None = None
    proof_digest: str | None = None
    head_digest: str | None = None


class AttestationSigner(ABC):
    """External signing boundary. Signing authenticity never grants execution authority."""

    algorithm: str
    issuer_id: str
    key_id: str

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """Return an encoded signature for immutable canonical attestation bytes."""


class AttestationVerifier(ABC):
    """External verification boundary. No global trust roots are embedded in OperationProof."""

    algorithm: str
    issuer_id: str
    key_id: str

    @abstractmethod
    def verify(self, payload: bytes, signature: str) -> bool:
        """Return True only when the configured external trust contract accepts the signature."""


def _text(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value) > 512
    ):
        raise ValueError(f"INVALID_ATTESTATION_FIELD:{field}")
    return value


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = canonical_json_bytes(dict(value))
        parsed = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, OverflowError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("INVALID_ATTESTATION_DOCUMENT") from exc
    if not isinstance(parsed, dict):
        raise ValueError("INVALID_ATTESTATION_DOCUMENT")
    return parsed


def attestation_payload(attestation: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(attestation)
    payload.pop("attestation_digest", None)
    return payload


def canonical_attestation_json(attestation: Mapping[str, Any]) -> str:
    snapshot = _snapshot(attestation)
    return canonical_json_bytes(snapshot).decode("utf-8")


def build_attestation(
    *,
    attestation_id: str,
    operation_id: str,
    subject_digest: str,
    proof_digest: str,
    artifact_type: str,
    artifact_digest: str,
    issuer_id: str,
    issued_at: str,
    sequence: int,
    previous_attestation_digest: str,
    payload_digest: str,
) -> dict[str, Any]:
    attestation: dict[str, Any] = {
        "schema": ATTESTATION_CONTRACT,
        "attestation_id": attestation_id,
        "operation_id": operation_id,
        "subject_digest": subject_digest,
        "proof_digest": proof_digest,
        "artifact_type": artifact_type,
        "artifact_digest": artifact_digest,
        "issuer_id": issuer_id,
        "issued_at": issued_at,
        "sequence": sequence,
        "previous_attestation_digest": previous_attestation_digest,
        "payload_digest": payload_digest,
    }
    attestation["attestation_digest"] = sha256_digest(attestation)
    result = verify_attestation_integrity(attestation, check_future=False)
    if not result.valid:
        raise ValueError("INVALID_ATTESTATION:" + ",".join(result.reason_codes))
    return attestation


def verify_attestation_integrity(
    attestation: Mapping[str, Any],
    *,
    now: datetime | None = None,
    max_future_skew_seconds: int = 0,
    check_future: bool = True,
) -> AttestationVerificationResult:
    reasons: list[str] = []
    if not isinstance(attestation, Mapping):
        return AttestationVerificationResult(False, ("ATTESTATION_MUST_BE_OBJECT",))

    try:
        snapshot = _snapshot(attestation)
    except ValueError as exc:
        return AttestationVerificationResult(False, (str(exc),))

    if snapshot.get("schema") != ATTESTATION_CONTRACT:
        reasons.append("UNSUPPORTED_ATTESTATION_SCHEMA")
    if set(snapshot) != _ATTESTATION_FIELDS:
        reasons.append("ATTESTATION_FIELD_SET_MISMATCH")

    for field in ("attestation_id", "operation_id", "artifact_type", "issuer_id"):
        try:
            _text(snapshot.get(field), field)
        except ValueError as exc:
            reasons.append(str(exc))

    for field in ("subject_digest", "proof_digest", "artifact_digest", "payload_digest"):
        value = snapshot.get(field)
        if not isinstance(value, str) or not valid_digest(value):
            reasons.append(f"INVALID_ATTESTATION_DIGEST:{field}")

    sequence = snapshot.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        reasons.append("INVALID_ATTESTATION_SEQUENCE")

    previous = snapshot.get("previous_attestation_digest")
    if sequence == 0:
        if previous != GENESIS:
            reasons.append("INVALID_ATTESTATION_GENESIS")
    elif not isinstance(previous, str) or not valid_digest(previous):
        reasons.append("INVALID_PREVIOUS_ATTESTATION_DIGEST")

    issued_at = snapshot.get("issued_at")
    issued = None
    try:
        issued = parse_rfc3339(issued_at)
    except (TypeError, ValueError):
        reasons.append("INVALID_ATTESTATION_ISSUED_AT")

    if check_future and issued is not None:
        if (
            not isinstance(max_future_skew_seconds, int)
            or isinstance(max_future_skew_seconds, bool)
        ):
            reasons.append("INVALID_ATTESTATION_FUTURE_SKEW")
        elif max_future_skew_seconds < 0 or max_future_skew_seconds > 300:
            reasons.append("INVALID_ATTESTATION_FUTURE_SKEW")
        else:
            reference = now or datetime.now(UTC)
            try:
                if reference.tzinfo is None or reference.utcoffset() is None:
                    raise ValueError("naive")
                limit = timestamp_from_datetime(
                    reference.astimezone(UTC) + timedelta(seconds=max_future_skew_seconds)
                )
                if compare_timestamps(issued, limit) > 0:
                    reasons.append("ATTESTATION_ISSUED_IN_FUTURE")
            except (TypeError, ValueError):
                reasons.append("INVALID_ATTESTATION_NOW")

    supplied = snapshot.get("attestation_digest")
    if not isinstance(supplied, str) or not valid_digest(supplied):
        reasons.append("INVALID_ATTESTATION_DIGEST:attestation_digest")
        supplied_value = None
    else:
        supplied_value = supplied
        if sha256_digest(attestation_payload(snapshot)) != supplied:
            reasons.append("ATTESTATION_DIGEST_MISMATCH")

    return AttestationVerificationResult(
        valid=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
        attestation_digest=supplied_value,
    )


def _signer_identity(adapter: object) -> tuple[str, str, str]:
    values: list[str] = []
    for field in ("algorithm", "issuer_id", "key_id"):
        try:
            value = getattr(adapter, field)
        except Exception as exc:
            raise ValueError(f"INVALID_SIGNATURE_ADAPTER:{field}") from exc
        if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
            raise ValueError(f"INVALID_SIGNATURE_ADAPTER:{field}")
        values.append(value)
    return values[0], values[1], values[2]


def sign_attestation(
    attestation: Mapping[str, Any],
    signer: AttestationSigner,
) -> dict[str, Any]:
    snapshot = _snapshot(attestation)
    integrity = verify_attestation_integrity(snapshot, check_future=False)
    if not integrity.valid:
        raise ValueError("INVALID_ATTESTATION:" + ",".join(integrity.reason_codes))

    algorithm, issuer_id, key_id = _signer_identity(signer)
    if issuer_id != snapshot.get("issuer_id"):
        raise ValueError("SIGNER_ISSUER_MISMATCH")

    payload = canonical_json_bytes(snapshot)
    try:
        signature = signer.sign(payload)
    except Exception as exc:
        raise ValueError("SIGNATURE_ADAPTER_FAILED") from exc
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        raise ValueError("MALFORMED_SIGNATURE_ADAPTER_OUTPUT")

    return {
        "schema": SIGNED_ATTESTATION_CONTRACT,
        "attestation": snapshot,
        "signature": {
            "schema": SIGNATURE_CONTRACT,
            "algorithm": algorithm,
            "issuer_id": issuer_id,
            "key_id": key_id,
            "attestation_digest": snapshot["attestation_digest"],
            "signature": signature,
        },
    }


def verify_attestation_signature(
    signed_attestation: Mapping[str, Any],
    verifier: AttestationVerifier,
    *,
    now: datetime | None = None,
    max_future_skew_seconds: int = 0,
) -> SignatureVerificationResult:
    reasons: list[str] = []
    if not isinstance(signed_attestation, Mapping):
        return SignatureVerificationResult(
            False, ("SIGNED_ATTESTATION_MUST_BE_OBJECT",), False, False
        )
    try:
        signed_snapshot = _snapshot(signed_attestation)
    except ValueError as exc:
        return SignatureVerificationResult(False, (str(exc),), False, False)
    if signed_snapshot.get("schema") != SIGNED_ATTESTATION_CONTRACT:
        reasons.append("UNSUPPORTED_SIGNED_ATTESTATION_SCHEMA")
    if set(signed_snapshot) != _SIGNED_ATTESTATION_FIELDS:
        reasons.append("SIGNED_ATTESTATION_FIELD_SET_MISMATCH")

    attestation = signed_snapshot.get("attestation")
    signature = signed_snapshot.get("signature")
    if not isinstance(attestation, Mapping):
        return SignatureVerificationResult(
            False,
            tuple(sorted(set(reasons + ["MISSING_SIGNED_ATTESTATION_PAYLOAD"]))),
            False,
            False,
        )
    integrity = verify_attestation_integrity(
        attestation,
        now=now,
        max_future_skew_seconds=max_future_skew_seconds,
    )
    reasons.extend(integrity.reason_codes)
    if not isinstance(signature, Mapping):
        return SignatureVerificationResult(
            False,
            tuple(sorted(set(reasons + ["MISSING_ATTESTATION_SIGNATURE"]))),
            integrity.valid,
            False,
        )

    if signature.get("schema") != SIGNATURE_CONTRACT:
        reasons.append("UNSUPPORTED_ATTESTATION_SIGNATURE_SCHEMA")
    if set(signature) != _SIGNATURE_FIELDS:
        reasons.append("ATTESTATION_SIGNATURE_FIELD_SET_MISMATCH")
    algorithm = signature.get("algorithm")
    issuer_id = signature.get("issuer_id")
    key_id = signature.get("key_id")
    encoded = signature.get("signature")
    signed_digest = signature.get("attestation_digest")

    try:
        expected_algorithm, expected_issuer, expected_key_id = _signer_identity(verifier)
    except ValueError as exc:
        reasons.append(str(exc))
        expected_algorithm = expected_issuer = expected_key_id = None

    if algorithm != expected_algorithm:
        reasons.append("SIGNATURE_ALGORITHM_MISMATCH")
    if issuer_id != attestation.get("issuer_id"):
        reasons.append("SIGNATURE_ISSUER_ATTESTATION_MISMATCH")
    if issuer_id != expected_issuer:
        reasons.append("SIGNATURE_ISSUER_TRUST_MISMATCH")
    if key_id != expected_key_id:
        reasons.append("SIGNATURE_KEY_ID_MISMATCH")
    if signed_digest != attestation.get("attestation_digest"):
        reasons.append("SIGNATURE_ATTESTATION_DIGEST_MISMATCH")
    if not isinstance(encoded, str) or not _SIGNATURE_RE.fullmatch(encoded):
        reasons.append("MALFORMED_ATTESTATION_SIGNATURE")

    signature_valid = False
    if not reasons and integrity.valid:
        payload = canonical_json_bytes(dict(attestation))
        try:
            result = verifier.verify(payload, encoded)
        except Exception:
            reasons.append("SIGNATURE_VERIFIER_FAILED")
        else:
            if not isinstance(result, bool):
                reasons.append("MALFORMED_SIGNATURE_VERIFIER_OUTPUT")
            elif result:
                signature_valid = True
            else:
                reasons.append("ATTESTATION_SIGNATURE_INVALID")

    return SignatureVerificationResult(
        valid=bool(integrity.valid and signature_valid and not reasons),
        reason_codes=tuple(sorted(set(reasons))),
        integrity_valid=integrity.valid,
        signature_valid=signature_valid,
        issuer_id=issuer_id if isinstance(issuer_id, str) else None,
        algorithm=algorithm if isinstance(algorithm, str) else None,
        key_id=key_id if isinstance(key_id, str) else None,
    )


def verify_provenance_chain(
    signed_attestations: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    *,
    verifiers: Mapping[tuple[str, str, str], AttestationVerifier],
    expected_operation_id: str | None = None,
    expected_subject_digest: str | None = None,
    expected_proof_digest: str | None = None,
    now: datetime | None = None,
) -> ProvenanceVerificationResult:
    if not isinstance(signed_attestations, (list, tuple)) or not signed_attestations:
        return ProvenanceVerificationResult(False, ("EMPTY_PROVENANCE_CHAIN",), 0)
    if not isinstance(verifiers, Mapping):
        return ProvenanceVerificationResult(
            False, ("INVALID_PROVENANCE_VERIFIER_REGISTRY",), len(signed_attestations)
        )

    reasons: list[str] = []
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    operation_id = subject_digest = proof_digest = head_digest = None
    previous_digest = GENESIS

    for index, signed in enumerate(signed_attestations):
        if not isinstance(signed, Mapping):
            reasons.append(f"INVALID_CHAIN_ENTRY:{index}")
            continue
        try:
            signed_snapshot = _snapshot(signed)
        except ValueError:
            reasons.append(f"INVALID_CHAIN_ENTRY:{index}")
            continue
        signature = signed_snapshot.get("signature")
        attestation = signed_snapshot.get("attestation")
        if not isinstance(signature, Mapping) or not isinstance(attestation, Mapping):
            reasons.append(f"INVALID_CHAIN_ENTRY:{index}")
            continue
        key = (
            signature.get("issuer_id"),
            signature.get("algorithm"),
            signature.get("key_id"),
        )
        verifier = verifiers.get(key) if all(isinstance(v, str) for v in key) else None
        if verifier is None:
            reasons.append(f"UNTRUSTED_ATTESTATION_SIGNER:{index}")
            integrity = verify_attestation_integrity(attestation, now=now)
        else:
            signed_result = verify_attestation_signature(signed_snapshot, verifier, now=now)
            reasons.extend(f"ENTRY_{index}:{code}" for code in signed_result.reason_codes)
            integrity = verify_attestation_integrity(attestation, now=now)

        att_id = attestation.get("attestation_id")
        att_digest = attestation.get("attestation_digest")
        if isinstance(att_id, str):
            if att_id in seen_ids:
                reasons.append("REPLAYED_ATTESTATION_ID")
            seen_ids.add(att_id)
        if isinstance(att_digest, str):
            if att_digest in seen_digests:
                reasons.append("REPLAYED_ATTESTATION_DIGEST")
            seen_digests.add(att_digest)
            head_digest = att_digest

        if attestation.get("sequence") != index:
            reasons.append("PROVENANCE_SEQUENCE_MISMATCH")
        if attestation.get("previous_attestation_digest") != previous_digest:
            reasons.append("BROKEN_PREDECESSOR_LINK")
        if isinstance(att_digest, str):
            previous_digest = att_digest

        current_operation = attestation.get("operation_id")
        current_subject = attestation.get("subject_digest")
        current_proof = attestation.get("proof_digest")
        if index == 0:
            operation_id = current_operation if isinstance(current_operation, str) else None
            subject_digest = current_subject if isinstance(current_subject, str) else None
            proof_digest = current_proof if isinstance(current_proof, str) else None
        else:
            if current_operation != operation_id:
                reasons.append("CROSS_OPERATION_TRANSPLANT")
            if current_subject != subject_digest:
                reasons.append("SUBJECT_TRANSPLANT")
            if current_proof != proof_digest:
                reasons.append("PROOF_TRANSPLANT")

        if not integrity.valid:
            reasons.extend(f"ENTRY_{index}:{code}" for code in integrity.reason_codes)

    if expected_operation_id is not None and operation_id != expected_operation_id:
        reasons.append("EXPECTED_OPERATION_ID_MISMATCH")
    if expected_subject_digest is not None and subject_digest != expected_subject_digest:
        reasons.append("EXPECTED_SUBJECT_DIGEST_MISMATCH")
    if expected_proof_digest is not None and proof_digest != expected_proof_digest:
        reasons.append("EXPECTED_PROOF_DIGEST_MISMATCH")

    unique_reasons = tuple(sorted(set(reasons)))
    return ProvenanceVerificationResult(
        valid=not unique_reasons,
        reason_codes=unique_reasons,
        attestation_count=len(signed_attestations),
        operation_id=operation_id,
        subject_digest=subject_digest,
        proof_digest=proof_digest,
        head_digest=head_digest,
    )


class HMACSHA256Signer(AttestationSigner):
    """Reference/test adapter only; it is not a global OperationProof trust root."""

    algorithm = HMAC_SHA256_V1

    def __init__(self, *, issuer_id: str, key_id: str, secret: bytes) -> None:
        self.issuer_id = _text(issuer_id, "issuer_id")
        self.key_id = _text(key_id, "key_id")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("INVALID_REFERENCE_HMAC_SECRET")
        self._secret = bytes(secret)

    def sign(self, payload: bytes) -> str:
        digest = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class HMACSHA256Verifier(AttestationVerifier):
    """Reference/test verifier paired with an explicitly supplied external secret."""

    algorithm = HMAC_SHA256_V1

    def __init__(self, *, issuer_id: str, key_id: str, secret: bytes) -> None:
        self.issuer_id = _text(issuer_id, "issuer_id")
        self.key_id = _text(key_id, "key_id")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("INVALID_REFERENCE_HMAC_SECRET")
        self._secret = bytes(secret)

    def verify(self, payload: bytes, signature: str) -> bool:
        expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
        return hmac.compare_digest(encoded, signature)
