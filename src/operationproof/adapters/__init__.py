"""Built-in adapters for external OperationProof evidence providers."""

from ..provider import ProviderAdapterManifest, ProviderAdapterRegistry
from .caser import CaserExecutionAdapter, CaserExecutionError
from .howedo import HowedoWitnessAdapter, HowedoWitnessError
from .vone import (
    VOneAuthorizationError,
    VOneExecutionGrantAdapter,
    make_vone_execution_grant_trust_verifier,
)

HOWEDO_ADAPTER_MANIFEST = ProviderAdapterManifest(
    adapter_id="operationproof.howedo.v1",
    provider_id=HowedoWitnessAdapter.provider_id,
    layer=HowedoWitnessAdapter.layer,
    native_protocols=(
        HowedoWitnessAdapter.protocol,
        HowedoWitnessAdapter.binding_protocol,
    ),
)

VONE_ADAPTER_MANIFEST = ProviderAdapterManifest(
    adapter_id="operationproof.vone.authorization.v1",
    provider_id=VOneExecutionGrantAdapter.provider_id,
    layer=VOneExecutionGrantAdapter.layer,
    native_protocols=(VOneExecutionGrantAdapter.protocol,),
)

CASER_ADAPTER_MANIFEST = ProviderAdapterManifest(
    adapter_id="operationproof.caser-execution.v1",
    provider_id=CaserExecutionAdapter.provider_id,
    layer=CaserExecutionAdapter.layer,
    native_protocols=(
        CaserExecutionAdapter.receipt_protocol,
        CaserExecutionAdapter.verification_protocol,
        CaserExecutionAdapter.binding_protocol,
    ),
)

BUILTIN_PROVIDER_ADAPTERS = ProviderAdapterRegistry()
for _manifest in (
    HOWEDO_ADAPTER_MANIFEST,
    VONE_ADAPTER_MANIFEST,
    CASER_ADAPTER_MANIFEST,
):
    BUILTIN_PROVIDER_ADAPTERS.register(_manifest)

__all__ = [
    "BUILTIN_PROVIDER_ADAPTERS",
    "CASER_ADAPTER_MANIFEST",
    "CaserExecutionAdapter",
    "CaserExecutionError",
    "HOWEDO_ADAPTER_MANIFEST",
    "HowedoWitnessAdapter",
    "HowedoWitnessError",
    "VONE_ADAPTER_MANIFEST",
    "VOneAuthorizationError",
    "VOneExecutionGrantAdapter",
    "make_vone_execution_grant_trust_verifier",
]
