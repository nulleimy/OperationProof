from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .attestation import GENESIS, verify_attestation_integrity
from .canonical import canonical_json_bytes, valid_digest


def _snapshot_signed(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        parsed = json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    except (TypeError, ValueError, OverflowError, json.JSONDecodeError, RecursionError) as exc:
        raise AttestationStoreError("INVALID_SIGNED_ATTESTATION") from exc
    if not isinstance(parsed, dict):
        raise AttestationStoreError("INVALID_SIGNED_ATTESTATION")
    return parsed


class AttestationStoreError(RuntimeError):
    """Raised when a provenance append cannot be validated atomically."""


@dataclass(frozen=True, slots=True)
class AttestationStoreHead:
    operation_id: str
    subject_digest: str
    proof_digest: str
    sequence: int
    attestation_id: str
    attestation_digest: str


class AttestationStore(ABC):
    """Provider-neutral durable provenance store contract.

    Production adapters must make append atomic across sequence, predecessor,
    attestation id, and attestation digest uniqueness.
    """

    @abstractmethod
    def head(self, operation_id: str) -> AttestationStoreHead | None:
        """Return the current operation chain head, or None for genesis."""

    @abstractmethod
    def append(
        self,
        signed_attestation: Mapping[str, Any],
        *,
        expected_sequence: int,
        expected_previous_attestation_digest: str,
    ) -> AttestationStoreHead:
        """Atomically append only when the caller's expected chain position still matches."""

    @abstractmethod
    def read(self, operation_id: str, sequence: int) -> Mapping[str, Any] | None:
        """Read back one persisted chain entry for post-append validation."""


def validate_attestation_store_head(
    value: object,
    *,
    expected_operation_id: str,
    expected_subject_digest: str,
    expected_proof_digest: str,
    expected_sequence: int,
    expected_attestation_id: str | None = None,
    expected_attestation_digest: str | None = None,
) -> AttestationStoreHead:
    if not isinstance(value, AttestationStoreHead):
        raise AttestationStoreError("INVALID_ATTESTATION_STORE_OUTPUT")
    if (
        not isinstance(value.operation_id, str)
        or not value.operation_id
        or value.operation_id != value.operation_id.strip()
        or "\x00" in value.operation_id
        or not isinstance(value.attestation_id, str)
        or not value.attestation_id
        or value.attestation_id != value.attestation_id.strip()
        or "\x00" in value.attestation_id
        or not isinstance(value.sequence, int)
        or isinstance(value.sequence, bool)
        or value.sequence < 0
        or not valid_digest(value.subject_digest)
        or not valid_digest(value.proof_digest)
        or not valid_digest(value.attestation_digest)
    ):
        raise AttestationStoreError("INVALID_ATTESTATION_STORE_OUTPUT")
    if value.operation_id != expected_operation_id:
        raise AttestationStoreError("ATTESTATION_STORE_OPERATION_MISMATCH")
    if value.subject_digest != expected_subject_digest:
        raise AttestationStoreError("ATTESTATION_STORE_SUBJECT_MISMATCH")
    if value.proof_digest != expected_proof_digest:
        raise AttestationStoreError("ATTESTATION_STORE_PROOF_MISMATCH")
    if value.sequence != expected_sequence:
        raise AttestationStoreError("ATTESTATION_STORE_SEQUENCE_MISMATCH")
    if expected_attestation_id is not None and value.attestation_id != expected_attestation_id:
        raise AttestationStoreError("ATTESTATION_STORE_ID_MISMATCH")
    if (
        expected_attestation_digest is not None
        and value.attestation_digest != expected_attestation_digest
    ):
        raise AttestationStoreError("ATTESTATION_STORE_DIGEST_MISMATCH")
    return value


class MemoryAttestationStore(AttestationStore):
    """Single-process reference store for tests/dev; not a production durability claim."""

    def __init__(self, *, max_attestations: int = 10_000) -> None:
        if (
            not isinstance(max_attestations, int)
            or isinstance(max_attestations, bool)
            or max_attestations <= 0
        ):
            raise AttestationStoreError("INVALID_ATTESTATION_STORE_CAPACITY")
        self._max_attestations = max_attestations
        self._heads: dict[str, AttestationStoreHead] = {}
        self._records: dict[str, list[dict[str, Any]]] = {}
        self._seen_ids: set[str] = set()
        self._seen_digests: set[str] = set()
        self._lock = threading.Lock()

    def head(self, operation_id: str) -> AttestationStoreHead | None:
        if not isinstance(operation_id, str) or not operation_id:
            raise AttestationStoreError("INVALID_ATTESTATION_OPERATION_ID")
        with self._lock:
            return self._heads.get(operation_id)

    def append(
        self,
        signed_attestation: Mapping[str, Any],
        *,
        expected_sequence: int,
        expected_previous_attestation_digest: str,
    ) -> AttestationStoreHead:
        if not isinstance(signed_attestation, Mapping):
            raise AttestationStoreError("INVALID_SIGNED_ATTESTATION")
        snapshot = _snapshot_signed(signed_attestation)
        attestation = snapshot.get("attestation")
        if not isinstance(attestation, Mapping):
            raise AttestationStoreError("INVALID_SIGNED_ATTESTATION")
        integrity = verify_attestation_integrity(attestation, check_future=False)
        if not integrity.valid:
            raise AttestationStoreError("INVALID_ATTESTATION_IN_STORE")

        operation_id = attestation.get("operation_id")
        subject_digest = attestation.get("subject_digest")
        proof_digest = attestation.get("proof_digest")
        sequence = attestation.get("sequence")
        attestation_id = attestation.get("attestation_id")
        attestation_digest = attestation.get("attestation_digest")
        previous = attestation.get("previous_attestation_digest")
        if not all(
            isinstance(value, str)
            for value in (
                operation_id,
                subject_digest,
                proof_digest,
                attestation_id,
                attestation_digest,
                previous,
            )
        ):
            raise AttestationStoreError("INVALID_ATTESTATION_IN_STORE")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise AttestationStoreError("INVALID_ATTESTATION_IN_STORE")

        with self._lock:
            total = sum(len(records) for records in self._records.values())
            if total >= self._max_attestations:
                raise AttestationStoreError("ATTESTATION_STORE_CAPACITY_EXCEEDED")
            current = self._heads.get(operation_id)
            actual_sequence = 0 if current is None else current.sequence + 1
            actual_previous = GENESIS if current is None else current.attestation_digest
            if expected_sequence != actual_sequence or sequence != actual_sequence:
                raise AttestationStoreError("ATTESTATION_SEQUENCE_CONFLICT")
            if (
                expected_previous_attestation_digest != actual_previous
                or previous != actual_previous
            ):
                raise AttestationStoreError("ATTESTATION_PREDECESSOR_CONFLICT")
            if current is not None:
                if current.subject_digest != subject_digest:
                    raise AttestationStoreError("ATTESTATION_SUBJECT_TRANSPLANT")
                if current.proof_digest != proof_digest:
                    raise AttestationStoreError("ATTESTATION_PROOF_TRANSPLANT")
            if attestation_id in self._seen_ids or attestation_digest in self._seen_digests:
                raise AttestationStoreError("ATTESTATION_REPLAY_DETECTED")

            head = AttestationStoreHead(
                operation_id=operation_id,
                subject_digest=subject_digest,
                proof_digest=proof_digest,
                sequence=sequence,
                attestation_id=attestation_id,
                attestation_digest=attestation_digest,
            )
            self._seen_ids.add(attestation_id)
            self._seen_digests.add(attestation_digest)
            self._records.setdefault(operation_id, []).append(snapshot)
            self._heads[operation_id] = head
            return head

    def read(self, operation_id: str, sequence: int) -> Mapping[str, Any] | None:
        if not isinstance(operation_id, str) or not operation_id:
            raise AttestationStoreError("INVALID_ATTESTATION_OPERATION_ID")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise AttestationStoreError("INVALID_ATTESTATION_SEQUENCE")
        with self._lock:
            records = self._records.get(operation_id, ())
            if sequence >= len(records):
                return None
            return _snapshot_signed(records[sequence])

    def records(self, operation_id: str) -> tuple[dict[str, Any], ...]:
        """Test/dev inspection only; returns copies and is not an authority API."""
        with self._lock:
            return tuple(_snapshot_signed(item) for item in self._records.get(operation_id, ()))
