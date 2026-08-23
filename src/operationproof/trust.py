from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .domain import Layer
from .verifier import verify_proof

EvidenceTrustVerifier = Callable[[Mapping[str, Any]], bool]


@dataclass(frozen=True, slots=True)
class TrustVerificationResult:
    trusted: bool
    reason_codes: tuple[str, ...]


@dataclass(slots=True)
class ProviderTrustRegistry:
    """Trusted out-of-band mapping from canonical provider identities to verifiers.

    The registry itself is deployment configuration. It must never be populated from
    fields carried inside an untrusted OperationProof.
    """

    _verifiers: dict[tuple[str, str], EvidenceTrustVerifier] = field(default_factory=dict)

    @staticmethod
    def _layer_name(layer: Layer | str) -> str:
        value = layer.value if isinstance(layer, Layer) else layer
        if not isinstance(value, str) or not value:
            raise ValueError("INVALID_TRUST_LAYER")
        if value not in {item.value for item in Layer}:
            raise ValueError("UNKNOWN_TRUST_LAYER")
        return value

    def register(
        self,
        *,
        layer: Layer | str,
        provider: str,
        verifier: EvidenceTrustVerifier,
    ) -> None:
        layer_name = self._layer_name(layer)
        if not isinstance(provider, str) or not provider:
            raise ValueError("INVALID_TRUST_PROVIDER")
        if not callable(verifier):
            raise ValueError("INVALID_TRUST_VERIFIER")

        key = (layer_name, provider)
        if key in self._verifiers:
            raise ValueError("DUPLICATE_PROVIDER_TRUST_ENTRY")
        self._verifiers[key] = verifier

    def verifier_for(self, *, layer: str, provider: str) -> EvidenceTrustVerifier | None:
        return self._verifiers.get((layer, provider))


def _verify_evidence_trust(
    item: Any,
    *,
    index: int,
    registry: ProviderTrustRegistry,
) -> list[str]:
    if not isinstance(item, Mapping):
        return [f"INVALID_TRUST_EVIDENCE_ENTRY:{index}"]

    layer = item.get("layer")
    provider = item.get("provider")
    if not isinstance(layer, str) or not layer:
        return [f"INVALID_TRUST_LAYER:{index}"]
    if not isinstance(provider, str) or not provider:
        return [f"INVALID_TRUST_PROVIDER:{layer}"]

    verifier = registry.verifier_for(layer=layer, provider=provider)
    if verifier is None:
        return [f"UNREGISTERED_PROVIDER:{layer}:{provider}"]

    try:
        trusted = verifier(item)
    except Exception:
        return [f"PROVIDER_TRUST_VERIFIER_ERROR:{layer}:{provider}"]

    if trusted is not True:
        return [f"UNTRUSTED_PROVIDER_EVIDENCE:{layer}:{provider}"]
    return []


def _collect_proof_evidence(proof: Mapping[str, Any]) -> list[Any]:
    phase = proof.get("phase")
    evidence: list[Any] = []

    if phase == "FINAL":
        pre_proof = proof.get("pre_proof")
        if isinstance(pre_proof, Mapping):
            evidence.extend(_collect_proof_evidence(pre_proof))

    current = proof.get("evidence")
    if isinstance(current, list):
        evidence.extend(current)
    return evidence


def verify_proof_trust(
    proof: dict[str, Any],
    registry: ProviderTrustRegistry,
) -> TrustVerificationResult:
    """Verify provider authenticity/trust after structural proof verification.

    This function is intentionally separate from ``verify_proof``. The structural
    verifier proves canonical integrity and deterministic semantics; this trust gate
    proves that every evidence provider is recognized by trusted deployment config
    and that its external verifier accepts the exact serialized evidence envelope.
    """

    integrity = verify_proof(proof)
    if not integrity.valid:
        reasons = ["PROOF_INTEGRITY_INVALID"]
        reasons.extend(f"PROOF_INTEGRITY:{code}" for code in integrity.reason_codes)
        return TrustVerificationResult(False, tuple(sorted(set(reasons))))

    if proof.get("decision") != "VERIFIED":
        return TrustVerificationResult(False, ("PROOF_NOT_VERIFIED",))

    reasons: list[str] = []
    for index, item in enumerate(_collect_proof_evidence(proof)):
        reasons.extend(_verify_evidence_trust(item, index=index, registry=registry))

    return TrustVerificationResult(
        trusted=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )
