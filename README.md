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

For raw untrusted JSON, prefer `assess_proof_json()` / `parse_proof_json()`. The strict parser rejects duplicate keys and non-finite JSON numbers before protocol verification. See `docs/SDK.md`.

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

## Local verification

```bash
python -m pip install -e '.[dev]'
pytest
operationproof-verify proof.json
```

`operationproof-verify` remains the low-level local integrity/semantic CLI and does not replace provider trust evaluation.
