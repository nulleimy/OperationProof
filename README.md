# OperationProof

**Vendor-neutral trust fabric and evidence connector for governed AI operations.**

OperationProof does not replace identity, authorization, continuity, tool-safety, data-flow, resource, or execution systems. It connects them, normalizes their evidence, binds evidence to one exact operation, verifies it fail-closed, and emits reproducible pre-operation and final proofs.

## Eight evidence layers

1. `identity` — who is acting?
2. `authorization` — is the actor allowed to perform the operation?
3. `intent` — is the operation aligned with the bound intent?
4. `continuity` — are the state and dependencies still valid?
5. `tool_safety` — is the exact tool invocation allowed?
6. `data_flow` — may the referenced data cross this boundary?
7. `resource` — is the operation within resource/budget limits?
8. `execution` — did the authorized operation execute as bound?

The first seven layers form a `PreOperationProof`. Execution evidence can exist only after execution and is bound into a `FinalOperationProof`.

## Verification gates

OperationProof deliberately separates proof integrity, semantic decision, and provider authenticity:

```text
verify_proof()        -> canonical structure, digests, deterministic semantics
verify_proof_trust()  -> trusted provider verification via out-of-band registry
assess_proof()        -> safe SDK composition of both gates
```

A structurally valid proof is not automatically trusted. The R7 SDK is fail-closed: `ProofAssessment.accepted` is true only when integrity is valid, the proof decision is `VERIFIED`, and provider trust was actually evaluated and returned trusted.

## SDK quick start

```python
from operationproof import assess_proof

assessment = assess_proof(proof, registry=trust_registry)
if assessment.accepted:
    execute_governed_operation()
```

Without a trust registry, the SDK reports `TRUST_NOT_EVALUATED` and `accepted=False`; it never promotes an integrity-only result into governed acceptance.

For raw untrusted JSON, prefer `assess_proof_json()` / `parse_proof_json()`. The strict parser rejects duplicate keys, non-finite JSON numbers, and excessive nesting before protocol verification. See `docs/SDK.md`.

## Sidecar quick start

R8 exposes the same SDK contract through an optional local HTTP sidecar:

```bash
python -m pip install -e '.[sidecar]'
operationproof-sidecar --trust-factory mydeployment.trust:build_registry
```

The default bind address is `127.0.0.1`. The trusted runtime refuses to start without an out-of-band `ProviderTrustRegistry` factory. `--allow-integrity-only` exists only as an explicit diagnostic mode and cannot make an untrusted proof `accepted=true`.

The sidecar provides `GET /healthz`, `GET /readyz`, and `POST /v1/assess`, bounds request bodies while streaming, rejects compressed request bodies, and does not expose mutable trust configuration over HTTP. See `docs/SIDECAR_RUNTIME.md`.

## Provider conformance

R9 adds a provider adapter framework without flattening provider-specific trust APIs. Every adapter declares an exact `operationproof.provider-adapter.v1` manifest and can be tested with the reusable `operationproof.provider-conformance.v1` runner.

```python
from operationproof import run_provider_conformance

report = run_provider_conformance(
    manifest,
    adapter_error=MyAdapterError,
    cases=my_cases,
)
assert report.passed, report.to_dict()
```

The mandatory profile covers valid normalization, operation-transplant rejection, untrusted authority, authority exceptions, caller-input mutation isolation, and deterministic output. A conformance PASS does not grant runtime provider trust. See `docs/PROVIDER_CONFORMANCE.md`.

## Gateway mode

R10 adds an active trusted gateway. It uses a two-step admission flow so a trusted PRE proof cannot become a replayable bearer capability:

```text
trusted PRE/v2 proof
        ↓
POST /v1/admissions
        ↓
one-time admission token
        ↓
/v1/proxy/<path>
        ↓
exact request digest == OperationSubject.target_digest
        ↓
fixed startup-configured upstream
```

Gateway mode has no integrity-only escape. It requires provider trust, a replay/admission store, expiry on every PRE evidence envelope, exact method/path/query/header/body binding, bounded request/response bodies, one-time token consumption, and a startup-only upstream URL. See `docs/GATEWAY_RUNTIME.md`.

## Signed provenance and observability

R11 adds canonical signed attestations and an append-only provenance chain without changing authority semantics.

```text
PRE proof
  ↓
proof_assessed
  ↓
admission_created
  ↓
admission_consumed
  ↓
upstream_dispatch_prepared
  ↓
expiry recheck
  ↓
upstream_dispatched
  ↓
upstream_completed | upstream_failed
  ↓
execution_receipt_verified
  ↓
final_proof_composed
```

`operationproof.attestation.v1` binds one operation, one subject, one PRE proof anchor, one related artifact, issuer identity, timestamp, sequence, predecessor digest, payload digest, and its own canonical digest. Signatures are evaluated through explicit external signer/verifier adapters; OperationProof ships no global trust root.

`upstream_dispatch_prepared` is a required durable pre-network barrier. The gateway rechecks admission expiry after that barrier and immediately before opening the upstream stream, so provenance persistence cannot reopen the R10 freshness TOCTOU window. `upstream_dispatched` is emitted only after the upstream stream is actually entered.

Signing does not imply `VERIFIED`, authorization, or execution success. Required provenance persistence is distinct from best-effort telemetry export. See `docs/ATTESTATIONS.md` and `docs/OBSERVABILITY.md`.

## Non-goals

OperationProof is not an IAM platform, policy engine, agent runtime, sandbox, DLP engine, observability backend, lineage platform, budget manager, or LLM judge. Providers remain external and are integrated through narrow adapters.

## Core rules

`UNKNOWN`, missing evidence, invalid digests, stale/expired evidence, operation mismatches, duplicate layer claims, unregistered providers, and provider-verifier failures are never promoted to success.

## Development baseline

R0-R1 establishes the protocol kernel: constitution, eight-layer evidence model, canonicalization, PRE/FINAL proofs, schemas, verifier, CLI, tests and CI.

R2 adds HOWEDO continuity evidence with a trusted operation/freshness binding.

R3 adds the provider trust gate: a fail-closed `(layer, provider)` registry and `verify_proof_trust()` so serialized evidence cannot become authoritative merely by claiming a provider name and recomputing local digests.

R4 adds `operationproof.execution-receipt.v1` and the CASER/SandCloud execution adapter with exact PRE-proof binding and fail-closed handling of integrity-only execution verification.

R5 integrates authoritative V-One `execution-grant/v2` authorization evidence while preserving V-One as the external authority and requiring trusted live verification.

G0 enables protected `main` and required deterministic CI gates.

R6 introduces canonical `OperationSubject`, subject-bound proof v2, downgrade protection, and externally verified native-provider-to-canonical subject bindings for HOWEDO, V-One, and CASER evidence.

R7 adds the stable SDK/library contract: strict raw JSON parsing, deterministic serialization, pinned package-root exports, detached caller input, and `ProofAssessment` so integrity cannot be confused with governed acceptance.

R8 adds the optional fail-closed sidecar API/runtime with trusted out-of-band registry bootstrap, loopback-only defaults, bounded HTTP input, liveness/readiness separation, and the same R7 acceptance semantics over HTTP.

R9 adds exact provider adapter manifests, duplicate-safe discovery, normalized-envelope validation, a reusable six-scenario conformance runner, first-party HOWEDO/V-One/CASER conformance suites, and detached HOWEDO authority-callback inputs.

R10 adds active gateway enforcement with canonical HTTP target binding, trusted PRE/v2 admission, one-time replay protection, startup-only upstream routing, bounded proxy I/O, and no integrity-only forwarding mode.

R11 adds canonical attestations, explicit external signature trust, append-only provenance with replay/order/transplant protection, structured digest-only observability, required provenance persistence, best-effort telemetry, an expiry-safe pre-dispatch provenance barrier, R10 gateway lifecycle integration, and execution/FINAL provenance helpers.

## Local verification

```bash
python -m pip install -e '.[dev]'
pytest
operationproof-verify proof.json
```

`operationproof-verify` remains the low-level local integrity/semantic CLI and does not replace provider trust evaluation.
