"""OperationProof core protocol."""

from .builder import build_final_proof, build_pre_proof
from .domain import EvidenceEnvelope, Layer, ProofDecision, Verdict
from .execution import (
    ExecutionEffect,
    ExecutionOutcome,
    ExecutionReceiptVerificationResult,
    build_execution_receipt,
    verify_execution_receipt,
)
from .trust import (
    ProviderTrustRegistry,
    TrustVerificationContext,
    TrustVerificationResult,
    verify_proof_trust,
)
from .verifier import VerificationResult, verify_proof

__all__ = [
    "EvidenceEnvelope",
    "ExecutionEffect",
    "ExecutionOutcome",
    "ExecutionReceiptVerificationResult",
    "Layer",
    "ProofDecision",
    "ProviderTrustRegistry",
    "TrustVerificationContext",
    "TrustVerificationResult",
    "Verdict",
    "VerificationResult",
    "build_execution_receipt",
    "build_final_proof",
    "build_pre_proof",
    "verify_execution_receipt",
    "verify_proof",
    "verify_proof_trust",
]
