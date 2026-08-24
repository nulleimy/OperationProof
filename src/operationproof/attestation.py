from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .canonical import canonical_json_bytes, sha256_digest, valid_digest
from .execution import verify_execution_receipt
from .rfc3339 import parse_rfc3339
from .verifier import verify_proof

PROVENANCE_STATEMENT_SCHEMA = "operationproof.provenance-statement.v1"
SIGNED_ATTESTATION_SCHEMA = "operationproof.signed-attestation.v1"
ATTESTATION_ALGORITHM_ED25519 = "ed25519"
_SIGNATURE_PREFIX = "b64url:"
_SIGNATURE_DOMAIN = b"OperationProof Signed Attestation v1\x00"


class ProvenanceArtifactType(StrEnum):
    PRE_PROOF = "PRE_PROOF"
    GATEWAY_ADMISSION = "GATEWAY_ADMISSION"
    GATEWAY_FORWARD = "GATEWAY_FORWARD"
    EXECUTION_RECEIPT = "EXECUTION_RECEIPT"
    FINAL_PROOF = "FINAL_PROOF"
    GENERIC = "GENERIC"


class AttestationError(ValueError):
    """Raised when a provenance statement or signed attestation is malformed."""


class AttestationTrustError(ValueError):
    """Raised when a verifier registry is configured ambiguously."""


@dataclass(frozen=True, slots=True)
class AttestationVerificationResult:
    valid: bool
    trusted: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AttestationChainVerificationResult:
    valid: bool
    trusted: bool
    reason_codes: tuple[str, ...]
    attestation_digests: tuple[str, ...]


def _snapshot_mapping(value: Mapping[str, Any], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AttestationError(code)
    try:
        encoded = canonical_json_bytes(dict(value))
        decoded = json.loads(encoded.decode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError, json.JSONDecodeError) as exc:
        raise AttestationError(code) from exc
    if not isinstance(decoded, dict):
        raise AttestationError(code)
    return decoded


def _nonempty_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise AttestationError(code)
    return value


def _artifact_type(value: ProvenanceArtifactType | str) -> str:
    raw = value.value if isinstance(value, ProvenanceArtifactType) else value
    if raw not in {item.value for item in ProvenanceArtifactType}:
        raise AttestationError("INVALID_PROVENANCE_ARTIFACT_TYPE")
    return raw


def provenance_statement_payload(statement: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(statement)
    payload.pop("statement_digest", None)
    return payload


def signed_attestation_payload(attestation: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(attestation)
    payload.pop("attestation_digest", None)
    return payload


def build_provenance_statement(
    *,
    operation_id: str,
    subject_digest: str,
    artifact_type: ProvenanceArtifactType | str,
    artifact_digest: str,
    producer: str,
    issued_at: str,
    predecessor_attestation_digest: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    operation = _nonempty_text(operation_id, "INVALID_PROVENANCE_OPERATION_ID")
    producer_value = _nonempty_text(producer, "INVALID_PROVENANCE_PRODUCER")
    if not isinstance(subject_digest, str) or not valid_digest(subject_digest):
        raise AttestationError("INVALID_PROVENANCE_SUBJECT_DIGEST")
    if not isinstance(artifact_digest, str) or not valid_digest(artifact_digest):
        raise AttestationError("INVALID_PROVENANCE_ARTIFACT_DIGEST")
    if predecessor_attestation_digest is not None and (
        not isinstance(predecessor_attestation_digest, str)
        or not valid_digest(predecessor_attestation_digest)
    ):
        raise AttestationError("INVALID_PREDECESSOR_ATTESTATION_DIGEST")
    try:
        parse_rfc3339(issued_at)
    except (TypeError, ValueError) as exc:
        raise AttestationError("INVALID_PROVENANCE_ISSUED_AT") from exc
    metadata_snapshot = _snapshot_mapping(metadata or {}, "INVALID_PROVENANCE_METADATA")
    statement: dict[str, Any] = {
        "schema": PROVENANCE_STATEMENT_SCHEMA,
        "operation_id": operation,
        "subject_digest": subject_digest,
        "artifact_type": _artifact_type(artifact_type),
        "artifact_digest": artifact_digest,
        "producer": producer_value,
        "issued_at": issued_at,
        "predecessor_attestation_digest": predecessor_attestation_digest,
        "metadata": metadata_snapshot,
    }
    statement["statement_digest"] = sha256_digest(statement)
    return statement


def verify_provenance_statement(statement: Mapping[str, Any]) -> AttestationVerificationResult:
    reasons: list[str] = []
    try:
        snapshot = _snapshot_mapping(statement, "INVALID_PROVENANCE_STATEMENT")
    except AttestationError as exc:
        return AttestationVerificationResult(False, False, (str(exc),))

    if snapshot.get("schema") != PROVENANCE_STATEMENT_SCHEMA:
        reasons.append("UNSUPPORTED_PROVENANCE_STATEMENT_SCHEMA")
    for field_name in ("operation_id", "producer"):
        value = snapshot.get(field_name)
        if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
            reasons.append(f"INVALID_PROVENANCE_FIELD:{field_name}")
    if snapshot.get("artifact_type") not in {item.value for item in ProvenanceArtifactType}:
        reasons.append("INVALID_PROVENANCE_ARTIFACT_TYPE")
    for field_name in ("subject_digest", "artifact_digest", "statement_digest"):
        value = snapshot.get(field_name)
        if not isinstance(value, str) or not valid_digest(value):
            reasons.append(f"INVALID_PROVENANCE_DIGEST:{field_name}")
    predecessor = snapshot.get("predecessor_attestation_digest")
    if predecessor is not None and (not isinstance(predecessor, str) or not valid_digest(predecessor)):
        reasons.append("INVALID_PREDECESSOR_ATTESTATION_DIGEST")
    try:
        parse_rfc3339(snapshot.get("issued_at"))
    except (TypeError, ValueError):
        reasons.append("INVALID_PROVENANCE_ISSUED_AT")
    if not isinstance(snapshot.get("metadata"), Mapping):
        reasons.append("INVALID_PROVENANCE_METADATA")
    supplied = snapshot.get("statement_digest")
    if isinstance(supplied, str) and valid_digest(supplied):
        expected = sha256_digest(provenance_statement_payload(snapshot))
        if supplied != expected:
            reasons.append("PROVENANCE_STATEMENT_DIGEST_MISMATCH")
    return AttestationVerificationResult(
        valid=not reasons,
        trusted=False,
        reason_codes=tuple(sorted(set(reasons))),
    )


def build_proof_provenance_statement(
    proof: Mapping[str, Any],
    *,
    producer: str,
    issued_at: str,
    predecessor_attestation_digest: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    snapshot = _snapshot_mapping(proof, "INVALID_PROOF_FOR_PROVENANCE")
    verification = verify_proof(snapshot)
    if not verification.valid:
        raise AttestationError("INVALID_PROOF_FOR_PROVENANCE:" + ",".join(verification.reason_codes))
    if snapshot.get("schema") != "operationproof.operation-proof.v2":
        raise AttestationError("PROVENANCE_REQUIRES_PROOF_V2")
    phase = snapshot.get("phase")
    if phase == "PRE":
        artifact_type = ProvenanceArtifactType.PRE_PROOF
    elif phase == "FINAL":
        artifact_type = ProvenanceArtifactType.FINAL_PROOF
    else:
        raise AttestationError("INVALID_PROOF_PHASE_FOR_PROVENANCE")
    operation_id = snapshot.get("operation_id")
    subject_digest = snapshot.get("subject_digest")
    proof_digest = snapshot.get("proof_digest")
    if not isinstance(operation_id, str) or not operation_id:
        raise AttestationError("INVALID_PROOF_OPERATION_ID_FOR_PROVENANCE")
    if not isinstance(subject_digest, str) or not valid_digest(subject_digest):
        raise AttestationError("INVALID_PROOF_SUBJECT_DIGEST_FOR_PROVENANCE")
    if not isinstance(proof_digest, str) or not valid_digest(proof_digest):
        raise AttestationError("INVALID_PROOF_DIGEST_FOR_PROVENANCE")
    return build_provenance_statement(
        operation_id=operation_id,
        subject_digest=subject_digest,
        artifact_type=artifact_type,
        artifact_digest=proof_digest,
        producer=producer,
        issued_at=issued_at,
        predecessor_attestation_digest=predecessor_attestation_digest,
        metadata=metadata,
    )


def build_execution_receipt_provenance_statement(
    receipt: Mapping[str, Any],
    *,
    subject_digest: str,
    producer: str,
    issued_at: str,
    predecessor_attestation_digest: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    snapshot = _snapshot_mapping(receipt, "INVALID_EXECUTION_RECEIPT_FOR_PROVENANCE")
    result = verify_execution_receipt(snapshot)
    if not result.valid:
        raise AttestationError(
            "INVALID_EXECUTION_RECEIPT_FOR_PROVENANCE:" + ",".join(result.reason_codes)
        )
    operation_id = snapshot.get("operation_id")
    receipt_digest = snapshot.get("receipt_digest")
    if not isinstance(operation_id, str) or not operation_id:
        raise AttestationError("INVALID_EXECUTION_OPERATION_ID_FOR_PROVENANCE")
    if not isinstance(receipt_digest, str) or not valid_digest(receipt_digest):
        raise AttestationError("INVALID_EXECUTION_RECEIPT_DIGEST_FOR_PROVENANCE")
    return build_provenance_statement(
        operation_id=operation_id,
        subject_digest=subject_digest,
        artifact_type=ProvenanceArtifactType.EXECUTION_RECEIPT,
        artifact_digest=receipt_digest,
        producer=producer,
        issued_at=issued_at,
        predecessor_attestation_digest=predecessor_attestation_digest,
        metadata=metadata,
    )


def _signature_payload(statement: Mapping[str, Any]) -> bytes:
    return _SIGNATURE_DOMAIN + canonical_json_bytes(dict(statement))


def _encode_signature(value: bytes) -> str:
    return _SIGNATURE_PREFIX + base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str) or not value.startswith(_SIGNATURE_PREFIX):
        raise AttestationError("INVALID_ATTESTATION_SIGNATURE_ENCODING")
    encoded = value[len(_SIGNATURE_PREFIX) :]
    if not encoded or len(encoded) > 2048:
        raise AttestationError("INVALID_ATTESTATION_SIGNATURE_ENCODING")
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AttestationError("INVALID_ATTESTATION_SIGNATURE_ENCODING") from exc
    if not decoded:
        raise AttestationError("INVALID_ATTESTATION_SIGNATURE_ENCODING")
    return decoded


class AttestationSigner:
    @property
    def algorithm(self) -> str:
        raise NotImplementedError

    @property
    def key_id(self) -> str:
        raise NotImplementedError

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError


class Ed25519AttestationSigner(AttestationSigner):
    def __init__(self, *, key_id: str, private_key: bytes) -> None:
        self._key_id = _nonempty_text(key_id, "INVALID_ATTESTATION_KEY_ID")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise AttestationError("INVALID_ED25519_PRIVATE_KEY")
        self._private_key = bytes(private_key)

    @property
    def algorithm(self) -> str:
        return ATTESTATION_ALGORITHM_ED25519

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ModuleNotFoundError as exc:
            raise AttestationError(
                "ATTESTATION_CRYPTO_DEPENDENCY_MISSING:install operationproof[attestations]"
            ) from exc
        return Ed25519PrivateKey.from_private_bytes(self._private_key).sign(payload)


VerifierCallback = Callable[[bytes, bytes], bool]


class AttestationTrustRegistry:
    def __init__(self) -> None:
        self._verifiers: dict[tuple[str, str], VerifierCallback] = {}

    def register(
        self,
        *,
        algorithm: str,
        key_id: str,
        verifier: VerifierCallback,
    ) -> None:
        algorithm_value = _nonempty_text(algorithm, "INVALID_ATTESTATION_ALGORITHM")
        key_value = _nonempty_text(key_id, "INVALID_ATTESTATION_KEY_ID")
        if not callable(verifier):
            raise AttestationTrustError("ATTESTATION_VERIFIER_NOT_CALLABLE")
        key = (algorithm_value, key_value)
        if key in self._verifiers:
            raise AttestationTrustError("DUPLICATE_ATTESTATION_VERIFIER")
        self._verifiers[key] = verifier

    def get(self, *, algorithm: str, key_id: str) -> VerifierCallback | None:
        return self._verifiers.get((algorithm, key_id))

    def register_ed25519_public_key(self, *, key_id: str, public_key: bytes) -> None:
        key_value = _nonempty_text(key_id, "INVALID_ATTESTATION_KEY_ID")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise AttestationTrustError("INVALID_ED25519_PUBLIC_KEY")
        public_key_snapshot = bytes(public_key)

        def verify(payload: bytes, signature: bytes) -> bool:
            try:
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            except ModuleNotFoundError as exc:
                raise AttestationTrustError(
                    "ATTESTATION_CRYPTO_DEPENDENCY_MISSING:install operationproof[attestations]"
                ) from exc
            try:
                Ed25519PublicKey.from_public_bytes(public_key_snapshot).verify(signature, payload)
            except InvalidSignature:
                return False
            return True

        self.register(
            algorithm=ATTESTATION_ALGORITHM_ED25519,
            key_id=key_value,
            verifier=verify,
        )


def sign_provenance_statement(
    statement: Mapping[str, Any],
    signer: AttestationSigner,
) -> dict[str, Any]:
    verification = verify_provenance_statement(statement)
    if not verification.valid:
        raise AttestationError("INVALID_PROVENANCE_STATEMENT:" + ",".join(verification.reason_codes))
    if not isinstance(signer, AttestationSigner):
        raise AttestationError("INVALID_ATTESTATION_SIGNER")
    snapshot = _snapshot_mapping(statement, "INVALID_PROVENANCE_STATEMENT")
    algorithm = _nonempty_text(signer.algorithm, "INVALID_ATTESTATION_ALGORITHM")
    key_id = _nonempty_text(signer.key_id, "INVALID_ATTESTATION_KEY_ID")
    try:
        signature = signer.sign(_signature_payload(snapshot))
    except AttestationError:
        raise
    except Exception as exc:
        raise AttestationError("ATTESTATION_SIGNER_FAILED") from exc
    if not isinstance(signature, bytes) or not signature:
        raise AttestationError("INVALID_ATTESTATION_SIGNATURE")
    attestation: dict[str, Any] = {
        "schema": SIGNED_ATTESTATION_SCHEMA,
        "statement": snapshot,
        "statement_digest": snapshot["statement_digest"],
        "signature": {
            "algorithm": algorithm,
            "key_id": key_id,
            "value": _encode_signature(signature),
        },
    }
    attestation["attestation_digest"] = sha256_digest(attestation)
    return attestation


def verify_signed_attestation(
    attestation: Mapping[str, Any],
    registry: AttestationTrustRegistry | None,
) -> AttestationVerificationResult:
    reasons: list[str] = []
    try:
        snapshot = _snapshot_mapping(attestation, "INVALID_SIGNED_ATTESTATION")
    except AttestationError as exc:
        return AttestationVerificationResult(False, False, (str(exc),))

    if snapshot.get("schema") != SIGNED_ATTESTATION_SCHEMA:
        reasons.append("UNSUPPORTED_SIGNED_ATTESTATION_SCHEMA")
    supplied_attestation_digest = snapshot.get("attestation_digest")
    if not isinstance(supplied_attestation_digest, str) or not valid_digest(
        supplied_attestation_digest
    ):
        reasons.append("INVALID_ATTESTATION_DIGEST")
    else:
        expected = sha256_digest(signed_attestation_payload(snapshot))
        if expected != supplied_attestation_digest:
            reasons.append("ATTESTATION_DIGEST_MISMATCH")

    statement = snapshot.get("statement")
    if not isinstance(statement, Mapping):
        reasons.append("INVALID_ATTESTATION_STATEMENT")
    else:
        statement_result = verify_provenance_statement(statement)
        reasons.extend(f"STATEMENT:{code}" for code in statement_result.reason_codes)
        if snapshot.get("statement_digest") != statement.get("statement_digest"):
            reasons.append("ATTESTATION_STATEMENT_DIGEST_MISMATCH")

    signature = snapshot.get("signature")
    algorithm: str | None = None
    key_id: str | None = None
    signature_bytes: bytes | None = None
    if not isinstance(signature, Mapping):
        reasons.append("INVALID_ATTESTATION_SIGNATURE")
    else:
        algorithm_value = signature.get("algorithm")
        key_value = signature.get("key_id")
        if not isinstance(algorithm_value, str) or not algorithm_value:
            reasons.append("INVALID_ATTESTATION_ALGORITHM")
        else:
            algorithm = algorithm_value
        if not isinstance(key_value, str) or not key_value:
            reasons.append("INVALID_ATTESTATION_KEY_ID")
        else:
            key_id = key_value
        try:
            signature_bytes = _decode_signature(signature.get("value"))
        except AttestationError as exc:
            reasons.append(str(exc))

    trusted = False
    if not reasons and isinstance(statement, Mapping):
        if registry is None or not isinstance(registry, AttestationTrustRegistry):
            reasons.append("ATTESTATION_TRUST_NOT_EVALUATED")
        elif algorithm is not None and key_id is not None and signature_bytes is not None:
            verifier = registry.get(algorithm=algorithm, key_id=key_id)
            if verifier is None:
                reasons.append("ATTESTATION_VERIFIER_NOT_FOUND")
            else:
                payload = _signature_payload(_snapshot_mapping(statement, "INVALID_ATTESTATION_STATEMENT"))
                try:
                    trusted = verifier(payload, bytes(signature_bytes)) is True
                except Exception:
                    reasons.append("ATTESTATION_VERIFIER_FAILED")
                if not trusted and "ATTESTATION_VERIFIER_FAILED" not in reasons:
                    reasons.append("ATTESTATION_SIGNATURE_INVALID")

    return AttestationVerificationResult(
        valid=not reasons,
        trusted=trusted and not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )


def verify_attestation_chain(
    attestations: Sequence[Mapping[str, Any]],
    registry: AttestationTrustRegistry,
    *,
    expected_operation_id: str | None = None,
    expected_subject_digest: str | None = None,
) -> AttestationChainVerificationResult:
    reasons: list[str] = []
    digests: list[str] = []
    if not isinstance(attestations, Sequence) or isinstance(attestations, (str, bytes, bytearray)):
        return AttestationChainVerificationResult(False, False, ("INVALID_ATTESTATION_CHAIN",), ())
    if not attestations:
        return AttestationChainVerificationResult(False, False, ("EMPTY_ATTESTATION_CHAIN",), ())

    operation_id = expected_operation_id
    subject_digest = expected_subject_digest
    previous_digest: str | None = None
    seen: set[str] = set()
    all_trusted = True

    for index, item in enumerate(attestations):
        result = verify_signed_attestation(item, registry)
        if not result.valid or not result.trusted:
            all_trusted = False
            reasons.extend(f"ATTESTATION[{index}]:{code}" for code in result.reason_codes)
            continue
        snapshot = _snapshot_mapping(item, "INVALID_SIGNED_ATTESTATION")
        digest = snapshot.get("attestation_digest")
        statement = snapshot.get("statement")
        if not isinstance(digest, str) or not valid_digest(digest) or not isinstance(statement, Mapping):
            all_trusted = False
            reasons.append(f"ATTESTATION[{index}]:INVALID_CHAIN_MEMBER")
            continue
        digests.append(digest)
        if digest in seen:
            reasons.append(f"ATTESTATION[{index}]:DUPLICATE_ATTESTATION_DIGEST")
        seen.add(digest)
        item_operation = statement.get("operation_id")
        item_subject = statement.get("subject_digest")
        if operation_id is None:
            operation_id = item_operation if isinstance(item_operation, str) else None
        if subject_digest is None:
            subject_digest = item_subject if isinstance(item_subject, str) else None
        if item_operation != operation_id:
            reasons.append(f"ATTESTATION[{index}]:OPERATION_ID_MISMATCH")
        if item_subject != subject_digest:
            reasons.append(f"ATTESTATION[{index}]:SUBJECT_DIGEST_MISMATCH")
        predecessor = statement.get("predecessor_attestation_digest")
        if index == 0:
            if predecessor is not None:
                reasons.append("ATTESTATION[0]:UNEXPECTED_PREDECESSOR")
        elif predecessor != previous_digest:
            reasons.append(f"ATTESTATION[{index}]:PREDECESSOR_DIGEST_MISMATCH")
        previous_digest = digest

    return AttestationChainVerificationResult(
        valid=all_trusted and not reasons and len(digests) == len(attestations),
        trusted=all_trusted and not reasons and len(digests) == len(attestations),
        reason_codes=tuple(sorted(set(reasons))),
        attestation_digests=tuple(digests),
    )
