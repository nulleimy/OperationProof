from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .domain import Layer
from .verifier import verify_proof


@dataclass(frozen=True, slots=True)
class TrustVerificationContext:
    """Trusted context derived from one structurally verified proof scope."""

    root_phase: str
    evidence_phase: str
    operation_id: str
    proof_digest: str
    pre_proof_digest: str | None
    evidence_index: int


EvidenceTrustVerifier = Callable[[Mapping[str, Any], TrustVerificationContext], bool]


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
            raise TypeError("INVALID_TRUST_VERIFIER")

        key = (layer_name, provider)
        if key in self._verifiers:
            raise ValueError("DUPLICATE_PROVIDER_TRUST_ENTRY")
        self._verifiers[key] = verifier

    def verifier_for(self, *, layer: str, provider: str) -> EvidenceTrustVerifier | None:
        return self._verifiers.get((layer, provider))


def _verify_evidence_trust(
    item: Any,
    *,
    context: TrustVerificationContext,
    registry: ProviderTrustRegistry,
) -> list[str]:
    if not isinstance(item, Mapping):
        return [f"INVALID_TRUST_EVIDENCE_ENTRY:{context.evidence_index}"]

    layer = item.get("layer")
    provider = item.get("provider")
    if not isinstance(layer, str) or not layer:
        return [f"INVALID_TRUST_LAYER:{context.evidence_index}"]
    if not isinstance(provider, str) or not provider:
        return [f"INVALID_TRUST_PROVIDER:{layer}"]

    verifier = registry.verifier_for(layer=layer, provider=provider)
    if verifier is None:
        return [f"UNREGISTERED_PROVIDER:{layer}:{provider}"]

    try:
        trusted = verifier(item, context)
    except Exception:  # noqa: BLE001 - external verifier boundary must fail closed
        return [f"PROVIDER_TRUST_VERIFIER_ERROR:{layer}:{provider}"]

    if trusted is not True:
        return [f"UNTRUSTED_PROVIDER_EVIDENCE:{layer}:{provider}"]
    return []


def verify_proof_trust(
    proof: dict[str, Any],
    registry: ProviderTrustRegistry,
) -> TrustVerificationResult:
    """Verify provider authenticity after structural proof verification.

    PRE evidence is always verified in the PRE proof's own trusted context. FINAL
    verification first requires that exact embedded PRE proof to pass recursively,
    then verifies only FINAL execution evidence with the outer FINAL context. This
    prevents a FINAL wrapper from changing the trust context under which PRE evidence
    is evaluated.
    """

    integrity = verify_proof(proof)
    if not integrity.valid:
        reasons = ["PROOF_INTEGRITY_INVALID"]
        reasons.extend(f"PROOF_INTEGRITY:{code}" for code in integrity.reason_codes)
        return TrustVerificationResult(False, tuple(sorted(set(reasons))))

    if proof.get("decision") != "VERIFIED":
        return TrustVerificationResult(False, ("PROOF_NOT_VERIFIED",))

    root_phase = str(proof.get("phase"))
    operation_id = str(proof.get("operation_id"))
    proof_digest = str(proof.get("proof_digest"))
    pre_proof_digest_raw = proof.get("pre_proof_digest")
    pre_proof_digest = (
        str(pre_proof_digest_raw)
        if root_phase == "FINAL" and isinstance(pre_proof_digest_raw, str)
        else None
    )

    reasons: list[str] = []

    if root_phase == "FINAL":
        pre_proof = proof.get("pre_proof")
        if not isinstance(pre_proof, dict):
            return TrustVerificationResult(False, ("INVALID_TRUST_PRE_PROOF",))
        pre_result = verify_proof_trust(pre_proof, registry)
        reasons.extend(pre_result.reason_codes)

    evidence = proof.get("evidence")
    if not isinstance(evidence, list):
        reasons.append("INVALID_TRUST_EVIDENCE_COLLECTION")
    else:
        for index, item in enumerate(evidence):
            context = TrustVerificationContext(
                root_phase=root_phase,
                evidence_phase=root_phase,
                operation_id=operation_id,
                proof_digest=proof_digest,
                pre_proof_digest=pre_proof_digest,
                evidence_index=index,
            )
            reasons.extend(
                _verify_evidence_trust(item, context=context, registry=registry)
            )

    return TrustVerificationResult(
        trusted=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )
