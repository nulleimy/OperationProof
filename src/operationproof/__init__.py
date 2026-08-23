"""OperationProof core protocol."""

from .builder import build_final_proof, build_pre_proof
from .domain import EvidenceEnvelope, Layer, ProofDecision, Verdict
from .trust import (
    ProviderTrustRegistry,
    TrustVerificationContext,
    TrustVerificationResult,
    verify_proof_trust,
)
from .verifier import VerificationResult, verify_proof

__all__ = [
    "EvidenceEnvelope",
    "Layer",
    "ProofDecision",
    "ProviderTrustRegistry",
    "TrustVerificationContext",
    "TrustVerificationResult",
    "Verdict",
    "VerificationResult",
    "build_final_proof",
    "build_pre_proof",
    "verify_proof",
    "verify_proof_trust",
]
