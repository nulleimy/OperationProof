# Provider adapter conformance

R9 defines two public contracts:

- `operationproof.provider-adapter.v1` — discovery/normalization manifest for one adapter.
- `operationproof.provider-conformance.v1` — executable CI report for the mandatory adapter profile.

These contracts do **not** make a provider trusted. Runtime authenticity remains the responsibility of `ProviderTrustRegistry` and its out-of-band provider verifier.

## Why the framework does not standardize `adapt(...)`

HOWEDO, V-One, and CASER have intentionally different authority boundaries:

- HOWEDO requires an externally verified continuity binding.
- V-One requires an authoritative `execution-grant/v2` verifier and has separate post-execution consumption semantics.
- CASER requires a verified PRE proof plus receipt, independent verification, and execution binding.

Flattening these into a generic `dict[str, object]` callback bag would erase useful type and trust boundaries. R9 therefore standardizes the **outer contract** while preserving provider-specific typed adapter APIs.

## Manifest

Every adapter declares:

```text
adapter_id
provider_id
layer
native_protocols
trust_boundary = EXTERNAL_VERIFIER_REQUIRED
subject_binding = NATIVE_THEN_CANONICAL_BINDING
output_schema = operationproof.evidence-envelope.v1
```

`ProviderAdapterRegistry` is an exact `(layer, provider_id)` discovery registry. It is not a trust registry and cannot authorize evidence.

Built-in manifests are available from `operationproof.adapters`:

```python
from operationproof.adapters import BUILTIN_PROVIDER_ADAPTERS

for manifest in BUILTIN_PROVIDER_ADAPTERS.manifests():
    print(manifest.to_dict())
```

## Output validation

`validate_adapter_output(...)` verifies that an adapter returned a canonical `EvidenceEnvelope` matching its declared provider, layer, output schema, exact operation id, digest formats, RFC3339 timestamps, and JSON canonicalizability.

This is a normalization contract only. It does not replace provider trust verification.

## Mandatory conformance profile

A provider suite must supply exactly one case for each scenario:

1. `VALID` — trusted valid native evidence normalizes successfully.
2. `OPERATION_MISMATCH` — an operation transplant fails closed with the adapter's declared error type.
3. `UNTRUSTED_AUTHORITY` — an external authority returning anything other than literal `True` fails closed.
4. `AUTHORITY_ERROR` — an authority callback exception fails closed through the adapter error boundary.
5. `MUTATION_ISOLATION` — authority callbacks cannot mutate caller-owned provider documents used by the adapter.
6. `DETERMINISM` — identical fixed inputs produce byte-identical canonical envelopes.

The expectations are fixed by the runner. Adapter authors cannot mark a failure scenario as successful in their case definition.

```python
from operationproof import run_provider_conformance

report = run_provider_conformance(
    manifest,
    adapter_error=MyAdapterError,
    cases=my_cases,
)
assert report.passed, report.to_dict()
```

The report is deterministic JSON-compatible evidence suitable for CI logs or later release attestations.

## First-party baseline

R9 runs the same generic profile against:

- `operationproof.howedo.v1`
- `operationproof.vone.authorization.v1`
- `operationproof.caser-execution.v1`

R9 also aligns HOWEDO with the existing V-One/CASER snapshot boundary: the external HOWEDO binding verifier receives a detached copy rather than the caller-owned binding document.

## Security boundary

A conformance PASS means only that the adapter obeys the OperationProof adapter contract under the supplied suite. It does not imply:

- the external provider is trustworthy;
- a proof is semantically `VERIFIED`;
- a runtime deployment is authorized;
- a provider verifier is correctly configured;
- a provider's native claims are stronger than their documented assurance level.

Those decisions remain in the existing proof, trust, subject-binding, and authority layers.
