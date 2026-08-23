from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from ..canonical import canonical_json_bytes, sha256_digest, valid_digest
from ..domain import EvidenceEnvelope, Layer, Verdict
from ..trust import TrustVerificationContext

_GRANT_TYPE = "execution-grant/v2"
_PROVIDER_ID = "vone"
_REQUIRED_PERMISSION = "execution.run"
_ONE_TIME_USE = "ONE_TIME"
_MAX_GRANT_TTL_SECONDS = 300
_MAX_PRECONDITION_TO_GRANT_SECONDS = 30
_PRECONDITION_CLASSES = {"READ_THEN_COMPARE", "ATOMIC_PROVIDER_CONDITION"}
_NATIVE_DIGEST_FIELDS = frozenset(
    {
        "authorization_snapshot_digest",
        "snapshot_authority_witness_set_digest",
        "snapshot_authority_event_hash",
        "parent_scope_digest",
        "authority_constraint_digest",
        "monotonic_authority_decision_digest",
        "capability_definition_identity",
        "target_digest",
        "payload_digest",
        "policy_identity",
        "approval_set_digest",
        "precondition_requirement_digest",
        "precondition_expectation_digest",
        "precondition_observation_digest",
        "precondition_witness_digest",
        "execution_binding_digest",
        "execution_capsule_digest",
        "grant_digest",
    }
)
_GRANT_FIELDS = frozenset(
    {
        "schema_version",
        "grant_type",
        "grant_id",
        "jti",
        "execution_id",
        "request_id",
        "authorization_snapshot_digest",
        "snapshot_authority_witness_set_digest",
        "snapshot_authority_event_hash",
        "parent_scope_digest",
        "authority_constraint_digest",
        "monotonic_authority_decision_digest",
        "actor_id",
        "workspace_id",
        "environment",
        "capability",
        "capability_definition_identity",
        "target_kind",
        "target_digest",
        "payload_digest",
        "policy_version",
        "policy_identity",
        "approval_set_digest",
        "required_permission",
        "precondition_requirement_digest",
        "precondition_expectation_digest",
        "precondition_observation_digest",
        "precondition_witness_digest",
        "precondition_enforcement_class",
        "precondition_checked_at",
        "execution_binding_digest",
        "execution_capsule_digest",
        "runner_class",
        "execution_binding_authority_revision",
        "issued_at",
        "expires_at",
        "revocation_epoch",
        "use_semantics",
        "issuer_identity",
        "issuer_revision",
        "grant_digest",
    }
)
_TEXT_FIELDS = frozenset(
    {
        "grant_id",
        "jti",
        "execution_id",
        "request_id",
        "actor_id",
        "workspace_id",
        "environment",
        "capability",
        "target_kind",
        "policy_version",
        "runner_class",
        "execution_binding_authority_revision",
        "issuer_identity",
        "issuer_revision",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "layer",
        "provider",
        "operation_id",
        "decision",
        "verdict",
        "subject_digest",
        "evidence_digest",
        "issued_at",
        "expires_at",
        "metadata",
    }
)
_METADATA_FIELDS = frozenset(
    {
        "adapter",
        "grant_protocol",
        "grant_id",
        "grant_jti",
        "grant_digest",
        "grant_document_digest",
        "authorization_snapshot_digest",
        "snapshot_authority_witness_set_digest",
        "snapshot_authority_event_hash",
        "precondition_witness_digest",
        "execution_binding_digest",
        "revocation_epoch",
        "issuer_identity",
        "issuer_revision",
    }
)


class VOneAuthorizationError(ValueError):
    """Raised when V-One authorization evidence cannot be normalized safely."""


GrantVerifier = Callable[[Mapping[str, Any]], bool]
GrantResolver = Callable[[str], Mapping[str, Any] | None]
Clock = Callable[[], datetime]


def _require_text(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        raise VOneAuthorizationError(code)
    return value


def _require_native_digest(value: object, code: str) -> str:
    text = _require_text(value, code)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise VOneAuthorizationError(code)
    return text


def _parse_vone_timestamp(value: object, code: str) -> datetime:
    text = _require_text(value, code)
    try:
        parsed = datetime.fromisoformat(text)
        offset = parsed.utcoffset()
        if parsed.tzinfo is None or offset is None:
            raise ValueError("timezone required")
        normalized = parsed.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise VOneAuthorizationError(code) from exc
    if text != normalized.isoformat(timespec="milliseconds"):
        raise VOneAuthorizationError(code)
    return normalized


def _native_grant_digest(grant: Mapping[str, Any]) -> str:
    payload = {key: grant[key] for key in _GRANT_FIELDS if key != "grant_digest"}
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _document_digest(grant: Mapping[str, Any]) -> str:
    return sha256_digest(dict(grant))


def _validate_grant(
    *,
    grant: Mapping[str, Any],
    operation_id: str,
    now: datetime,
) -> tuple[datetime, datetime, str]:
    if set(grant) != _GRANT_FIELDS:
        raise VOneAuthorizationError("INVALID_VONE_GRANT_FIELDS")
    if grant.get("schema_version") != 2 or grant.get("grant_type") != _GRANT_TYPE:
        raise VOneAuthorizationError("INVALID_VONE_GRANT_PROTOCOL")

    for field in _TEXT_FIELDS:
        _require_text(grant.get(field), f"INVALID_VONE_GRANT_FIELD:{field}")
    for field in _NATIVE_DIGEST_FIELDS:
        _require_native_digest(grant.get(field), f"INVALID_VONE_GRANT_DIGEST:{field}")

    if grant.get("execution_id") != operation_id:
        raise VOneAuthorizationError("VONE_EXECUTION_ID_MISMATCH")
    if grant.get("required_permission") != _REQUIRED_PERMISSION:
        raise VOneAuthorizationError("VONE_REQUIRED_PERMISSION_MISMATCH")
    if grant.get("use_semantics") != _ONE_TIME_USE:
        raise VOneAuthorizationError("VONE_USE_SEMANTICS_MISMATCH")
    if grant.get("precondition_enforcement_class") not in _PRECONDITION_CLASSES:
        raise VOneAuthorizationError("INVALID_VONE_PRECONDITION_ENFORCEMENT_CLASS")

    revocation_epoch = grant.get("revocation_epoch")
    if type(revocation_epoch) is not int or revocation_epoch < 0:
        raise VOneAuthorizationError("INVALID_VONE_REVOCATION_EPOCH")

    checked = _parse_vone_timestamp(
        grant.get("precondition_checked_at"),
        "INVALID_VONE_PRECONDITION_CHECKED_AT",
    )
    issued = _parse_vone_timestamp(grant.get("issued_at"), "INVALID_VONE_ISSUED_AT")
    expires = _parse_vone_timestamp(grant.get("expires_at"), "INVALID_VONE_EXPIRES_AT")
    if issued < checked:
        raise VOneAuthorizationError("VONE_GRANT_PREDATES_PRECONDITION")
    if expires <= issued:
        raise VOneAuthorizationError("INVALID_VONE_GRANT_TIME_WINDOW")
    if (expires - issued).total_seconds() > _MAX_GRANT_TTL_SECONDS:
        raise VOneAuthorizationError("VONE_GRANT_TTL_EXCEEDED")
    if (issued - checked).total_seconds() > _MAX_PRECONDITION_TO_GRANT_SECONDS:
        raise VOneAuthorizationError("VONE_PRECONDITION_TOO_OLD")
    try:
        now_utc = now.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise VOneAuthorizationError("INVALID_VERIFICATION_NOW") from exc
    if expires <= now_utc:
        raise VOneAuthorizationError("EXPIRED_VONE_GRANT")

    grant_digest = str(grant.get("grant_digest"))
    if grant_digest != _native_grant_digest(grant):
        raise VOneAuthorizationError("VONE_GRANT_DIGEST_MISMATCH")
    return issued, expires, _document_digest(grant)


def _evidence_from_grant(
    *,
    operation_id: str,
    grant: Mapping[str, Any],
    issued: datetime,
    expires: datetime,
    grant_document_digest: str,
) -> EvidenceEnvelope:
    subject_digest = sha256_digest(
        {
            "operation_id": operation_id,
            "authorization_snapshot_digest": grant["authorization_snapshot_digest"],
            "actor_id": grant["actor_id"],
            "workspace_id": grant["workspace_id"],
            "environment": grant["environment"],
            "capability": grant["capability"],
            "capability_definition_identity": grant["capability_definition_identity"],
            "target_digest": grant["target_digest"],
            "payload_digest": grant["payload_digest"],
        }
    )
    evidence_digest = sha256_digest(
        {
            "provider": _PROVIDER_ID,
            "grant_document_digest": grant_document_digest,
            "grant_digest": grant["grant_digest"],
        }
    )
    return EvidenceEnvelope(
        layer=Layer.AUTHORIZATION,
        provider=_PROVIDER_ID,
        operation_id=operation_id,
        decision=_GRANT_TYPE,
        verdict=Verdict.PASS,
        subject_digest=subject_digest,
        evidence_digest=evidence_digest,
        issued_at=issued.isoformat(timespec="milliseconds"),
        expires_at=expires.isoformat(timespec="milliseconds"),
        metadata={
            "adapter": "operationproof.vone.authorization.v1",
            "grant_protocol": _GRANT_TYPE,
            "grant_id": grant["grant_id"],
            "grant_jti": grant["jti"],
            "grant_digest": grant["grant_digest"],
            "grant_document_digest": grant_document_digest,
            "authorization_snapshot_digest": grant["authorization_snapshot_digest"],
            "snapshot_authority_witness_set_digest": (
                grant["snapshot_authority_witness_set_digest"]
            ),
            "snapshot_authority_event_hash": grant["snapshot_authority_event_hash"],
            "precondition_witness_digest": grant["precondition_witness_digest"],
            "execution_binding_digest": grant["execution_binding_digest"],
            "revocation_epoch": grant["revocation_epoch"],
            "issuer_identity": grant["issuer_identity"],
            "issuer_revision": grant["issuer_revision"],
        },
    )


class VOneExecutionGrantAdapter:
    """Normalize an authoritative V-One execution-grant/v2 into PRE authorization evidence."""

    layer = Layer.AUTHORIZATION
    provider_id = _PROVIDER_ID
    protocol = _GRANT_TYPE

    @classmethod
    def adapt(
        cls,
        *,
        operation_id: str,
        grant: Mapping[str, Any],
        grant_verifier: GrantVerifier,
        now: datetime | None = None,
    ) -> EvidenceEnvelope:
        operation_id = _require_text(operation_id, "INVALID_OPERATION_ID")
        if not isinstance(grant, Mapping):
            raise VOneAuthorizationError("INVALID_VONE_GRANT")
        if not callable(grant_verifier):
            raise VOneAuthorizationError("INVALID_VONE_GRANT_VERIFIER")
        now_value = now or datetime.now(UTC)

        issued, expires, grant_document_digest = _validate_grant(
            grant=grant,
            operation_id=operation_id,
            now=now_value,
        )
        try:
            trusted = grant_verifier(grant)
        except Exception as exc:  # fail closed across external authority failures
            raise VOneAuthorizationError("VONE_GRANT_VERIFICATION_ERROR") from exc
        if trusted is not True:
            raise VOneAuthorizationError("UNTRUSTED_VONE_GRANT")

        return _evidence_from_grant(
            operation_id=operation_id,
            grant=grant,
            issued=issued,
            expires=expires,
            grant_document_digest=grant_document_digest,
        )


def make_vone_execution_grant_trust_verifier(
    *,
    grant_resolver: GrantResolver,
    grant_verifier: GrantVerifier,
    clock: Clock | None = None,
) -> Callable[[Mapping[str, Any], TrustVerificationContext], bool]:
    """Build an R3 PRE provider-trust verifier backed by authoritative V-One grant lookup."""

    if not callable(grant_resolver):
        raise VOneAuthorizationError("INVALID_VONE_GRANT_RESOLVER")
    if not callable(grant_verifier):
        raise VOneAuthorizationError("INVALID_VONE_GRANT_VERIFIER")
    clock = clock or (lambda: datetime.now(UTC))
    if not callable(clock):
        raise VOneAuthorizationError("INVALID_VONE_CLOCK")

    def verify(
        envelope: Mapping[str, Any],
        context: TrustVerificationContext,
    ) -> bool:
        try:
            if context.root_phase != "PRE" or context.evidence_phase != "PRE":
                return False
            if context.pre_proof_digest is not None:
                return False
            if set(envelope) != _EVIDENCE_FIELDS:
                return False
            if envelope.get("layer") != Layer.AUTHORIZATION.value:
                return False
            if envelope.get("provider") != _PROVIDER_ID:
                return False
            if envelope.get("operation_id") != context.operation_id:
                return False

            metadata = envelope.get("metadata")
            if not isinstance(metadata, Mapping) or set(metadata) != _METADATA_FIELDS:
                return False
            if metadata.get("adapter") != "operationproof.vone.authorization.v1":
                return False
            if metadata.get("grant_protocol") != _GRANT_TYPE:
                return False
            grant_document_digest = metadata.get("grant_document_digest")
            if not isinstance(grant_document_digest, str) or not valid_digest(
                grant_document_digest
            ):
                return False

            grant = grant_resolver(grant_document_digest)
            if not isinstance(grant, Mapping):
                return False
            expected = VOneExecutionGrantAdapter.adapt(
                operation_id=context.operation_id,
                grant=grant,
                grant_verifier=grant_verifier,
                now=clock(),
            )
            return expected.to_dict() == dict(envelope)
        except Exception:  # noqa: BLE001 - provider trust boundary must fail closed
            return False

    return verify
