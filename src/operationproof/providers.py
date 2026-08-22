from __future__ import annotations

from typing import Any, Protocol

from .domain import EvidenceEnvelope, Layer


class ProviderAdapter(Protocol):
    """Narrow boundary implemented by concrete external-provider adapters."""

    layer: Layer
    provider_id: str

    def collect(self, operation: dict[str, Any]) -> EvidenceEnvelope:
        """Return canonical evidence for exactly one operation and one layer."""
        ...
