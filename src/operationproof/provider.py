from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json_bytes, valid_digest
from .domain import EvidenceEnvelope, Layer, Verdict
from .rfc3339 import compare_timestamps, parse_rfc3339

PROVIDER_ADAPTER_CONTRACT = "operationproof.provider-adapter.v1"
PROVIDER_MANIFEST_SCHEMA = "operationproof.provider-adapter-manifest.v1"
EVIDENCE_OUTPUT_SCHEMA = "operationproof.evidence-envelope.v1"
EXTERNAL_VERIFIER_TRUST = "EXTERNAL_VERIFIER_REQUIRED"
NATIVE_THEN_CANONICAL_SUBJECT = "NATIVE_THEN_CANONICAL_BINDING"


class ProviderAdapterContractError(ValueError):
    """Raised when a provider adapter manifest or registry entry is invalid."""


def _require_text(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        raise ProviderAdapterContractError(code)
    return value


@dataclass(frozen=True, slots=True)
class ProviderAdapterManifest:
    """Stable discovery contract for one external evidence adapter.

    The manifest describes the normalized boundary only. It deliberately does not
    standardize provider-specific authority callback signatures, because flattening
    those callbacks into a generic mapping would weaken existing trust boundaries.
    """

    adapter_id: str
    provider_id: str
    layer: Layer
    native_protocols: tuple[str, ...]
    trust_boundary: str = EXTERNAL_VERIFIER_TRUST
    subject_binding: str = NATIVE_THEN_CANONICAL_SUBJECT
    output_schema: str = EVIDENCE_OUTPUT_SCHEMA
    schema: str = PROVIDER_MANIFEST_SCHEMA
    contract: str = PROVIDER_ADAPTER_CONTRACT

    def __post_init__(self) -> None:
        _require_text(self.adapter_id, "INVALID_ADAPTER_ID")
        _require_text(self.provider_id, "INVALID_PROVIDER_ID")
        if not isinstance(self.layer, Layer):
            raise ProviderAdapterContractError("INVALID_ADAPTER_LAYER")
        if not isinstance(self.native_protocols, tuple) or not self.native_protocols:
            raise ProviderAdapterContractError("INVALID_NATIVE_PROTOCOLS")
        normalized: list[str] = []
        for protocol in self.native_protocols:
            normalized.append(_require_text(protocol, "INVALID_NATIVE_PROTOCOL"))
        if len(set(normalized)) != len(normalized):
            raise ProviderAdapterContractError("DUPLICATE_NATIVE_PROTOCOL")
        if self.trust_boundary != EXTERNAL_VERIFIER_TRUST:
            raise ProviderAdapterContractError("UNSUPPORTED_TRUST_BOUNDARY")
        if self.subject_binding != NATIVE_THEN_CANONICAL_SUBJECT:
            raise ProviderAdapterContractError("UNSUPPORTED_SUBJECT_BINDING_MODE")
        if self.output_schema != EVIDENCE_OUTPUT_SCHEMA:
            raise ProviderAdapterContractError("UNSUPPORTED_ADAPTER_OUTPUT_SCHEMA")
        if self.schema != PROVIDER_MANIFEST_SCHEMA:
            raise ProviderAdapterContractError("INVALID_PROVIDER_MANIFEST_SCHEMA")
        if self.contract != PROVIDER_ADAPTER_CONTRACT:
            raise ProviderAdapterContractError("INVALID_PROVIDER_ADAPTER_CONTRACT")

    @property
    def key(self) -> tuple[str, str]:
        return self.layer.value, self.provider_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "contract": self.contract,
            "adapter_id": self.adapter_id,
            "provider_id": self.provider_id,
            "layer": self.layer.value,
            "native_protocols": list(self.native_protocols),
            "trust_boundary": self.trust_boundary,
            "subject_binding": self.subject_binding,
            "output_schema": self.output_schema,
        }


@dataclass(frozen=True, slots=True)
class AdapterOutputValidationResult:
    valid: bool
    reason_codes: tuple[str, ...]


@dataclass(slots=True)
class ProviderAdapterRegistry:
    """Exact registry of supported normalized provider identities.

    This registry is discovery/configuration metadata only. It never grants provider
    trust and must not be confused with ``ProviderTrustRegistry``.
    """

    _manifests: dict[tuple[str, str], ProviderAdapterManifest] = field(default_factory=dict)

    def register(self, manifest: ProviderAdapterManifest) -> None:
        if not isinstance(manifest, ProviderAdapterManifest):
            raise TypeError("INVALID_PROVIDER_ADAPTER_MANIFEST")
        if manifest.key in self._manifests:
            raise ProviderAdapterContractError(
                f"DUPLICATE_PROVIDER_ADAPTER:{manifest.layer.value}:{manifest.provider_id}"
            )
        if any(existing.adapter_id == manifest.adapter_id for existing in self._manifests.values()):
            raise ProviderAdapterContractError(f"DUPLICATE_ADAPTER_ID:{manifest.adapter_id}")
        self._manifests[manifest.key] = manifest

    def manifest_for(self, *, layer: Layer | str, provider_id: str) -> ProviderAdapterManifest | None:
        layer_name = layer.value if isinstance(layer, Layer) else layer
        if not isinstance(layer_name, str) or not isinstance(provider_id, str):
            return None
        return self._manifests.get((layer_name, provider_id))

    def manifests(self) -> tuple[ProviderAdapterManifest, ...]:
        return tuple(
            sorted(
                self._manifests.values(),
                key=lambda item: (item.layer.value, item.provider_id, item.adapter_id),
            )
        )


def validate_adapter_output(
    manifest: ProviderAdapterManifest,
    envelope: object,
    *,
    expected_operation_id: str,
) -> AdapterOutputValidationResult:
    """Validate one normalized adapter result without granting semantic provider trust."""

    reasons: list[str] = []
    if not isinstance(manifest, ProviderAdapterManifest):
        return AdapterOutputValidationResult(False, ("INVALID_PROVIDER_ADAPTER_MANIFEST",))
    if not isinstance(expected_operation_id, str) or not expected_operation_id:
        return AdapterOutputValidationResult(False, ("INVALID_EXPECTED_OPERATION_ID",))
    if not isinstance(envelope, EvidenceEnvelope):
        return AdapterOutputValidationResult(False, ("ADAPTER_OUTPUT_NOT_EVIDENCE_ENVELOPE",))

    if envelope.schema != manifest.output_schema:
        reasons.append("ADAPTER_OUTPUT_SCHEMA_MISMATCH")
    if not isinstance(envelope.layer, Layer):
        reasons.append("INVALID_ADAPTER_OUTPUT_LAYER")
    elif envelope.layer is not manifest.layer:
        reasons.append("ADAPTER_OUTPUT_LAYER_MISMATCH")
    if envelope.provider != manifest.provider_id:
        reasons.append("ADAPTER_OUTPUT_PROVIDER_MISMATCH")
    if envelope.operation_id != expected_operation_id:
        reasons.append("ADAPTER_OUTPUT_OPERATION_ID_MISMATCH")
    if not isinstance(envelope.decision, str) or not envelope.decision:
        reasons.append("INVALID_ADAPTER_OUTPUT_DECISION")
    if not isinstance(envelope.verdict, Verdict):
        reasons.append("INVALID_ADAPTER_OUTPUT_VERDICT")
    if not isinstance(envelope.subject_digest, str) or not valid_digest(envelope.subject_digest):
        reasons.append("INVALID_ADAPTER_OUTPUT_SUBJECT_DIGEST")
    if not isinstance(envelope.evidence_digest, str) or not valid_digest(envelope.evidence_digest):
        reasons.append("INVALID_ADAPTER_OUTPUT_EVIDENCE_DIGEST")
    if not isinstance(envelope.metadata, dict):
        reasons.append("INVALID_ADAPTER_OUTPUT_METADATA")
    elif envelope.metadata.get("adapter") != manifest.adapter_id:
        reasons.append("ADAPTER_OUTPUT_ADAPTER_ID_MISMATCH")

    issued = None
    try:
        issued = parse_rfc3339(envelope.issued_at)
    except (TypeError, ValueError):
        reasons.append("INVALID_ADAPTER_OUTPUT_ISSUED_AT")

    if envelope.expires_at is not None:
        try:
            expires = parse_rfc3339(envelope.expires_at)
            if issued is not None and compare_timestamps(expires, issued) <= 0:
                reasons.append("INVALID_ADAPTER_OUTPUT_TIME_WINDOW")
        except (TypeError, ValueError):
            reasons.append("INVALID_ADAPTER_OUTPUT_EXPIRES_AT")

    try:
        canonical_json_bytes(envelope.to_dict())
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError):
        reasons.append("ADAPTER_OUTPUT_NOT_CANONICAL_JSON")

    return AdapterOutputValidationResult(
        valid=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )
