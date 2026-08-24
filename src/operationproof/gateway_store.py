from __future__ import annotations

import hashlib
import secrets
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .canonical import valid_digest


class GatewayAdmissionStoreError(RuntimeError):
    """Raised when a gateway admission cannot be reserved safely."""


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise GatewayAdmissionStoreError(code)
    return value


@dataclass(frozen=True, slots=True)
class GatewayAdmissionRecord:
    operation_id: str
    proof_digest: str
    subject_digest: str
    target_digest: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _text(self.operation_id, "INVALID_ADMISSION_OPERATION_ID")
        for value, code in (
            (self.proof_digest, "INVALID_ADMISSION_PROOF_DIGEST"),
            (self.subject_digest, "INVALID_ADMISSION_SUBJECT_DIGEST"),
            (self.target_digest, "INVALID_ADMISSION_TARGET_DIGEST"),
        ):
            if not isinstance(value, str) or not valid_digest(value):
                raise GatewayAdmissionStoreError(code)
        _text(self.issued_at, "INVALID_ADMISSION_ISSUED_AT")
        _text(self.expires_at, "INVALID_ADMISSION_EXPIRES_AT")


class GatewayAdmissionStore(ABC):
    """Atomic replay boundary for gateway operations, proofs, and one-time tokens."""

    @abstractmethod
    def reserve(self, record: GatewayAdmissionRecord) -> str:
        """Reserve one operation/proof exactly once and return an opaque admission token."""

    @abstractmethod
    def consume(self, token: str) -> GatewayAdmissionRecord | None:
        """Atomically consume a token exactly once and return its admission record."""


class MemoryGatewayAdmissionStore(GatewayAdmissionStore):
    """Single-process reference store for tests and explicitly ephemeral deployments.

    Operation ids and proof digests are retained for the process lifetime. Capacity
    exhaustion fails closed instead of evicting replay history.
    """

    def __init__(self, *, max_records: int = 10_000) -> None:
        if not isinstance(max_records, int) or isinstance(max_records, bool) or max_records <= 0:
            raise GatewayAdmissionStoreError("INVALID_ADMISSION_STORE_CAPACITY")
        self._max_records = max_records
        self._reserved_operations: set[str] = set()
        self._reserved_proofs: set[str] = set()
        self._tokens: dict[str, GatewayAdmissionRecord] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def reserve(self, record: GatewayAdmissionRecord) -> str:
        if not isinstance(record, GatewayAdmissionRecord):
            raise GatewayAdmissionStoreError("INVALID_ADMISSION_RECORD")
        with self._lock:
            if (
                record.operation_id in self._reserved_operations
                or record.proof_digest in self._reserved_proofs
            ):
                raise GatewayAdmissionStoreError("PROOF_REPLAY_DETECTED")
            if len(self._reserved_operations) >= self._max_records:
                raise GatewayAdmissionStoreError("ADMISSION_STORE_CAPACITY_EXCEEDED")
            for _ in range(8):
                token = secrets.token_urlsafe(32)
                token_digest = self._token_digest(token)
                if token_digest not in self._tokens:
                    self._reserved_operations.add(record.operation_id)
                    self._reserved_proofs.add(record.proof_digest)
                    self._tokens[token_digest] = record
                    return token
            raise GatewayAdmissionStoreError("ADMISSION_TOKEN_GENERATION_FAILED")

    def consume(self, token: str) -> GatewayAdmissionRecord | None:
        if not isinstance(token, str) or not token or token != token.strip() or "\x00" in token:
            return None
        token_digest = self._token_digest(token)
        with self._lock:
            return self._tokens.pop(token_digest, None)
