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
from .subject import OperationSubject, OperationSubjectError
from .subject_binding import (
    SubjectBindingError,
    bind_evidence_to_subject,
    make_subject_bound_trust_verifier,
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
    "OperationSubject",
    "OperationSubjectError",
    "ProofDecision",
    "ProviderTrustRegistry",
    "SubjectBindingError",
    "TrustVerificationContext",
    "TrustVerificationResult",
    "Verdict",
    "VerificationResult",
    "bind_evidence_to_subject",
    "build_execution_receipt",
    "build_final_proof",
    "build_pre_proof",
    "make_subject_bound_trust_verifier",
    "verify_execution_receipt",
    "verify_proof",
    "verify_proof_trust",
]
