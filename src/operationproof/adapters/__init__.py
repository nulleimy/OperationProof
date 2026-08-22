"""Built-in adapters for external OperationProof evidence providers."""

from .howedo import HowedoWitnessAdapter, HowedoWitnessError

__all__ = ["HowedoWitnessAdapter", "HowedoWitnessError"]
