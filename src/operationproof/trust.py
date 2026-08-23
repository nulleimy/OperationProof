from __future__ import annotations

from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Final

from .domain import Layer
from .verifier import verify_proof

DIRECT_VERIFICATION_STAGE: Final = "DIRECT"
EMBEDDED_PRE_OF_FINAL_STAGE: Final = "EMBEDDED_PRE_OF_FINAL"
_VERIFICATION_STAGE: ContextVar[str] = ContextVar(
    "operationproof_trust_verification_stage",
    default=DIRECT_VERIFICATION_STAGE,
)


@dataclass(frozen=True, slots=True)
class TrustVerificationContext:
    """Trusted context derived from one structurally verified proof scope.

    The dataclass field contract intentionally remains the original six-field R3
    contract. ``verification_stage`` is an ephemeral callback-time property backed
    by a private ContextVar, so legacy equality/hash/serialization behavior is not
    changed for non-stage-aware providers.
    """

    root_phase: str
    evidence_phase: str
    operation_id: str
    proof_digest: str
    pre_proof_digest: str | None
    evidence_index: int

    @property
    def verification_stage(self) -> str:
        """Return the trusted internal stage only while a verifier callback runs."""

        return _VERIFICATION_STAGE.get()


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
    verification_stage: str,
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

    token = _VERIFICATION_STAGE.set(verification_stage)
    try:
        trusted = verifier(item, context)
    except Exception:  # noqa: BLE001 - external verifier boundary must fail closed
        return [f"PROVIDER_TRUST_VERIFIER_ERROR:{layer}:{provider}"]
    finally:
        _VERIFICATION_STAGE.reset(token)

    if trusted is not True:
        return [f"UNTRUSTED_PROVIDER_EVIDENCE:{layer}:{provider}"]
    return []


def _verify_proof_trust_at_stage(
    proof: dict[str, Any],
    registry: ProviderTrustRegistry,
    *,
    verification_stage: str,
) -> TrustVerificationResult:
    if verification_stage not in {DIRECT_VERIFICATION_STAGE, EMBEDDED_PRE_OF_FINAL_STAGE}:
        return TrustVerificationResult(False, ("INVALID_TRUST_VERIFICATION_STAGE",))

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
        pre_result = _verify_proof_trust_at_stage(
            pre_proof,
            registry,
            verification_stage=EMBEDDED_PRE_OF_FINAL_STAGE,
        )
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
                _verify_evidence_trust(
                    item,
                    context=context,
                    registry=registry,
                    verification_stage=verification_stage,
                )
            )

    return TrustVerificationResult(
        trusted=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
    )


def verify_proof_trust(
    proof: dict[str, Any],
    registry: ProviderTrustRegistry,
) -> TrustVerificationResult:
    """Verify provider authenticity after structural proof verification.

    PRE evidence is always verified in the PRE proof's own trusted context. FINAL
    verification recursively verifies the exact embedded PRE proof with a trusted
    callback-time post-execution stage while retaining that PRE proof's own phase,
    digest, operation id, and absent ``pre_proof_digest``. The stage is not a
    serialized/dataclass field, preventing both proof-controlled stage laundering and
    compatibility drift for existing ProviderTrustRegistry users.
    """

    return _verify_proof_trust_at_stage(
        proof,
        registry,
        verification_stage=DIRECT_VERIFICATION_STAGE,
    )