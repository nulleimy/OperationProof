"""OperationProof public library API."""

from .builder import build_final_proof, build_pre_proof
from .domain import EvidenceEnvelope, Layer, ProofDecision, Verdict
from .execution import (
    ExecutionEffect,
    ExecutionOutcome,
    ExecutionReceiptVerificationResult,
    build_execution_receipt,
    verify_execution_receipt,
)
from .sdk import (
    SDK_CONTRACT,
    ProofAssessment,
    ProofDocumentError,
    assess_proof,
    assess_proof_json,
    canonical_proof_json,
    parse_proof_json,
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
    "ProofAssessment",
    "ProofDecision",
    "ProofDocumentError",
    "ProviderTrustRegistry",
    "SDK_CONTRACT",
    "SubjectBindingError",
    "TrustVerificationContext",
    "TrustVerificationResult",
    "Verdict",
    "VerificationResult",
    "assess_proof",
    "assess_proof_json",
    "bind_evidence_to_subject",
    "build_execution_receipt",
    "build_final_proof",
    "build_pre_proof",
    "canonical_proof_json",
    "make_subject_bound_trust_verifier",
    "parse_proof_json",
    "verify_execution_receipt",
    "verify_proof",
    "verify_proof_trust",
]
