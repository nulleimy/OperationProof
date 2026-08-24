"""OperationProof public library API."""

from .builder import build_final_proof, build_pre_proof
from .conformance import (
    CONFORMANCE_CONTRACT,
    ConformanceScenario,
    ProviderConformanceCase,
    ProviderConformanceCaseResult,
    ProviderConformanceError,
    ProviderConformanceReport,
    run_provider_conformance,
)
from .domain import EvidenceEnvelope, Layer, ProofDecision, Verdict
from .execution import (
    ExecutionEffect,
    ExecutionOutcome,
    ExecutionReceiptVerificationResult,
    build_execution_receipt,
    verify_execution_receipt,
)
from .gateway_contract import (
    GATEWAY_TARGET_CONTRACT,
    GatewayTarget,
    GatewayTargetError,
    build_gateway_target,
    canonical_gateway_headers,
    gateway_target_digest,
)
from .gateway_store import (
    GatewayAdmissionRecord,
    GatewayAdmissionStore,
    GatewayAdmissionStoreError,
    MemoryGatewayAdmissionStore,
)
from .provider import (
    PROVIDER_ADAPTER_CONTRACT,
    AdapterOutputValidationResult,
    ProviderAdapterContractError,
    ProviderAdapterManifest,
    ProviderAdapterRegistry,
    validate_adapter_output,
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
    "CONFORMANCE_CONTRACT",
    "GATEWAY_TARGET_CONTRACT",
    "PROVIDER_ADAPTER_CONTRACT",
    "SDK_CONTRACT",
    "AdapterOutputValidationResult",
    "ConformanceScenario",
    "EvidenceEnvelope",
    "ExecutionEffect",
    "ExecutionOutcome",
    "ExecutionReceiptVerificationResult",
    "GatewayAdmissionRecord",
    "GatewayAdmissionStore",
    "GatewayAdmissionStoreError",
    "GatewayTarget",
    "GatewayTargetError",
    "Layer",
    "MemoryGatewayAdmissionStore",
    "OperationSubject",
    "OperationSubjectError",
    "ProofAssessment",
    "ProofDecision",
    "ProofDocumentError",
    "ProviderAdapterContractError",
    "ProviderAdapterManifest",
    "ProviderAdapterRegistry",
    "ProviderConformanceCase",
    "ProviderConformanceCaseResult",
    "ProviderConformanceError",
    "ProviderConformanceReport",
    "ProviderTrustRegistry",
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
    "build_gateway_target",
    "build_pre_proof",
    "canonical_gateway_headers",
    "canonical_proof_json",
    "gateway_target_digest",
    "make_subject_bound_trust_verifier",
    "parse_proof_json",
    "run_provider_conformance",
    "validate_adapter_output",
    "verify_execution_receipt",
    "verify_proof",
    "verify_proof_trust",
]
