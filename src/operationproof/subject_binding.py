from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from .canonical import canonical_json_bytes, sha256_digest, valid_digest
from .domain import EvidenceEnvelope
from .rfc3339 import compare_timestamps, parse_rfc3339, timestamp_from_datetime
from .subject import OperationSubject
from .trust import EvidenceTrustVerifier, TrustVerificationContext

_BINDING_SCHEMA = "operationproof.subject-binding.v1"
_METADATA_KEY = "operationproof_subject_binding"
_BINDING_FIELDS = frozenset(
    {
        "schema",
        "operation_id",
        "layer",
        "provider",
        "native_envelope_digest",
        "native_subject_digest",
        "canonical_subject_digest",
        "issued_at",
        "expires_at",
        "binding_digest",
    }
)
_BINDING_METADATA_FIELDS = frozenset(
    {
        "protocol",
        "binding_digest",
        "native_envelope_digest",
        "native_subject_digest",
    }
)


class SubjectBindingError(ValueError):
    """Raised when provider evidence cannot be bound to a canonical subject safely."""


BindingVerifier = Callable[[Mapping[str, Any]], bool]
BindingResolver = Callable[[str], Mapping[str, Any] | None]
Clock = Callable[[], datetime]


def _snapshot(value: Mapping[str, Any], code: str) -> dict[str, Any]:
    try:
        snapshot = json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise SubjectBindingError(code) from exc
    if not isinstance(snapshot, dict):
        raise SubjectBindingError(code)
    return snapshot


def _binding_payload(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {key: binding[key] for key in _BINDING_FIELDS if key != "binding_digest"}


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or not valid_digest(value):
        raise SubjectBindingError(code)
    return value


def _validate_binding(
    *,
    binding: Mapping[str, Any],
    native_envelope: Mapping[str, Any],
    canonical_subject_digest: str,
    now: datetime,
) -> str:
    if set(binding) != _BINDING_FIELDS:
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_FIELDS")
    if binding.get("schema") != _BINDING_SCHEMA:
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_SCHEMA")

    native_subject_digest = _require_digest(
        native_envelope.get("subject_digest"),
        "INVALID_NATIVE_SUBJECT_DIGEST",
    )
    native_envelope_digest = sha256_digest(dict(native_envelope))
    expected = {
        "operation_id": native_envelope.get("operation_id"),
        "layer": native_envelope.get("layer"),
        "provider": native_envelope.get("provider"),
        "native_envelope_digest": native_envelope_digest,
        "native_subject_digest": native_subject_digest,
        "canonical_subject_digest": canonical_subject_digest,
    }
    for field, expected_value in expected.items():
        if binding.get(field) != expected_value:
            raise SubjectBindingError(f"SUBJECT_BINDING_MISMATCH:{field}")

    binding_digest = _require_digest(
        binding.get("binding_digest"),
        "INVALID_SUBJECT_BINDING_DIGEST",
    )
    if sha256_digest(_binding_payload(binding)) != binding_digest:
        raise SubjectBindingError("SUBJECT_BINDING_DIGEST_MISMATCH")

    try:
        issued = parse_rfc3339(binding.get("issued_at"))
        expires = parse_rfc3339(binding.get("expires_at"))
        verification_now = timestamp_from_datetime(now)
    except (TypeError, ValueError) as exc:
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_TIME") from exc
    if compare_timestamps(expires, issued) <= 0:
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_TIME_WINDOW")
    if compare_timestamps(issued, verification_now) > 0:
        raise SubjectBindingError("SUBJECT_BINDING_NOT_YET_VALID")
    if compare_timestamps(expires, verification_now) <= 0:
        raise SubjectBindingError("EXPIRED_SUBJECT_BINDING")

    return binding_digest


def bind_evidence_to_subject(
    envelope: EvidenceEnvelope,
    *,
    subject: OperationSubject,
    binding: Mapping[str, Any],
    binding_verifier: BindingVerifier,
    now: datetime | None = None,
) -> EvidenceEnvelope:
    """Bind one already-normalized provider envelope to a canonical OperationSubject.

    The bridge never treats a caller assertion as correlation evidence. The supplied
    binding must cover the exact native envelope digest and both native/canonical
    subject digests, and an external trusted verifier must authenticate it.
    """

    if not isinstance(envelope, EvidenceEnvelope):
        raise SubjectBindingError("INVALID_NATIVE_EVIDENCE")
    if not isinstance(subject, OperationSubject):
        raise SubjectBindingError("INVALID_OPERATION_SUBJECT")
    if envelope.operation_id != subject.operation_id:
        raise SubjectBindingError("SUBJECT_OPERATION_ID_MISMATCH")
    if not isinstance(binding, Mapping):
        raise SubjectBindingError("INVALID_SUBJECT_BINDING")
    if not callable(binding_verifier):
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_VERIFIER")

    native_envelope = _snapshot(envelope.to_dict(), "INVALID_NATIVE_EVIDENCE")
    binding_snapshot = _snapshot(binding, "INVALID_SUBJECT_BINDING")
    now_value = now or datetime.now(UTC)
    binding_digest = _validate_binding(
        binding=binding_snapshot,
        native_envelope=native_envelope,
        canonical_subject_digest=subject.digest,
        now=now_value,
    )

    try:
        verifier_binding = _snapshot(binding_snapshot, "INVALID_SUBJECT_BINDING")
        trusted = binding_verifier(verifier_binding)
    except Exception as exc:
        raise SubjectBindingError("SUBJECT_BINDING_VERIFICATION_ERROR") from exc
    if trusted is not True:
        raise SubjectBindingError("UNTRUSTED_SUBJECT_BINDING")

    metadata = _snapshot(envelope.metadata, "INVALID_NATIVE_EVIDENCE_METADATA")
    if _METADATA_KEY in metadata:
        raise SubjectBindingError("SUBJECT_BINDING_ALREADY_PRESENT")
    metadata[_METADATA_KEY] = {
        "protocol": _BINDING_SCHEMA,
        "binding_digest": binding_digest,
        "native_envelope_digest": sha256_digest(native_envelope),
        "native_subject_digest": envelope.subject_digest,
    }
    return replace(
        envelope,
        subject_digest=subject.digest,
        metadata=metadata,
    )


def make_subject_bound_trust_verifier(
    *,
    native_verifier: EvidenceTrustVerifier,
    binding_resolver: BindingResolver,
    binding_verifier: BindingVerifier,
    clock: Clock | None = None,
) -> EvidenceTrustVerifier:
    """Wrap an existing provider verifier with canonical subject correlation trust.

    The wrapper reconstructs the exact native envelope, verifies it with the original
    provider verifier, then independently resolves and authenticates the correlation
    binding. Repository proof data cannot self-authorize the subject mapping.
    """

    if not callable(native_verifier):
        raise SubjectBindingError("INVALID_NATIVE_TRUST_VERIFIER")
    if not callable(binding_resolver):
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_RESOLVER")
    if not callable(binding_verifier):
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_VERIFIER")
    clock = clock or (lambda: datetime.now(UTC))
    if not callable(clock):
        raise SubjectBindingError("INVALID_SUBJECT_BINDING_CLOCK")

    def verify(
        envelope: Mapping[str, Any],
        context: TrustVerificationContext,
    ) -> bool:
        try:
            bound = _snapshot(envelope, "INVALID_SUBJECT_BOUND_EVIDENCE")
            metadata = bound.get("metadata")
            if not isinstance(metadata, Mapping):
                return False
            metadata_snapshot = _snapshot(metadata, "INVALID_SUBJECT_BOUND_METADATA")
            marker = metadata_snapshot.pop(_METADATA_KEY, None)
            if not isinstance(marker, Mapping) or set(marker) != _BINDING_METADATA_FIELDS:
                return False
            if marker.get("protocol") != _BINDING_SCHEMA:
                return False

            canonical_subject_digest = _require_digest(
                bound.get("subject_digest"),
                "INVALID_CANONICAL_SUBJECT_DIGEST",
            )
            native_subject_digest = _require_digest(
                marker.get("native_subject_digest"),
                "INVALID_NATIVE_SUBJECT_DIGEST",
            )
            binding_digest = _require_digest(
                marker.get("binding_digest"),
                "INVALID_SUBJECT_BINDING_DIGEST",
            )

            native_envelope = dict(bound)
            native_envelope["subject_digest"] = native_subject_digest
            native_envelope["metadata"] = metadata_snapshot
            native_envelope_digest = sha256_digest(native_envelope)
            if marker.get("native_envelope_digest") != native_envelope_digest:
                return False

            native_for_verifier = _snapshot(
                native_envelope,
                "INVALID_NATIVE_EVIDENCE",
            )
            if native_verifier(native_for_verifier, context) is not True:
                return False

            resolved = binding_resolver(binding_digest)
            if not isinstance(resolved, Mapping):
                return False
            binding_snapshot = _snapshot(resolved, "INVALID_SUBJECT_BINDING")
            _validate_binding(
                binding=binding_snapshot,
                native_envelope=native_envelope,
                canonical_subject_digest=canonical_subject_digest,
                now=clock(),
            )
            if binding_snapshot.get("binding_digest") != binding_digest:
                return False

            verifier_binding = _snapshot(binding_snapshot, "INVALID_SUBJECT_BINDING")
            return binding_verifier(verifier_binding) is True
        except Exception:  # noqa: BLE001 - trust boundary is fail closed
            return False

    return verify
