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

## Non-goals

OperationProof is not an IAM platform, policy engine, agent runtime, sandbox, DLP engine, observability backend, lineage platform, budget manager, or LLM judge. Providers remain external and are integrated through narrow adapters.

## Core rule

`UNKNOWN`, missing evidence, invalid digests, stale/expired evidence, operation mismatches, and duplicate layer claims are never promoted to success.

## Development baseline

R0-R1 establishes:

- constitution and trust model;
- canonical eight-layer evidence model;
- deterministic JSON canonicalization and SHA-256 content addressing;
- fail-closed pre-operation composition;
- final proof binding to execution evidence;
- generic provider adapter protocol;
- core verifier and CLI;
- JSON Schemas;
- tests and CI.

## Local verification

```bash
python -m pip install -e '.[dev]'
pytest
operationproof-verify proof.json
```
