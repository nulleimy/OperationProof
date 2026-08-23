"""Built-in adapters for external OperationProof evidence providers."""

from .execution import (
    CaserExecutionReceiptAdapter,
    ExecutionReceiptError,
    SandCloudExecutionReceiptAdapter,
    make_execution_receipt_trust_verifier,
)
from .howedo import HowedoWitnessAdapter, HowedoWitnessError

__all__ = [
    "CaserExecutionReceiptAdapter",
    "ExecutionReceiptError",
    "HowedoWitnessAdapter",
    "HowedoWitnessError",
    "SandCloudExecutionReceiptAdapter",
    "make_execution_receipt_trust_verifier",
]
