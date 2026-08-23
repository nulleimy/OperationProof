# Execution Receipt Contract

R4 defines the first execution-provider boundary for OperationProof.

OperationProof does not execute workloads and does not replace SandCloud or CASER. It accepts a narrowly scoped provider receipt, validates its deterministic content binding, requires an external authenticity verifier, converts it into `execution` evidence, and later re-verifies the authoritative receipt through the R3 provider-trust gate.

## Canonical receipt

Schema: `operationproof.execution-receipt.v1`

Required fields:

- `provider`: `sandcloud` or `caser`
- `receipt_id`: provider-stable receipt identifier
- `operation_id`: exact OperationProof operation
- `pre_proof_digest`: exact PRE proof that authorized execution
- `status`: `SUCCEEDED`, `FAILED`, `CANCELLED`, or `UNKNOWN`
- `result_digest`: SHA-256 digest of the provider result/outcome record
- `started_at`: timezone-aware execution start
- `completed_at`: timezone-aware execution completion
- `receipt_digest`: SHA-256 over the canonical receipt payload excluding `receipt_digest`

The JSON Schema is `schemas/execution-receipt.v1.schema.json`.

## Status semantics

```text
SUCCEEDED -> PASS
FAILED    -> FAIL
CANCELLED -> FAIL
UNKNOWN   -> UNKNOWN
```

Only `PASS` execution evidence can produce a `VERIFIED` FinalOperationProof. Execution cannot authorize itself; the receipt must bind the exact PRE proof that already authorized the operation.

## Two trust moments

### Collection time

`SandCloudExecutionReceiptAdapter` and `CaserExecutionReceiptAdapter` require an external `receipt_verifier` before emitting evidence. A digest match alone is content integrity, not authenticity.

### Consumption time

R3 `verify_proof_trust()` must still authenticate serialized execution evidence. `make_execution_receipt_trust_verifier()` resolves the exact receipt from trusted deployment state, authenticates it out of band, and rebinds it to the structurally verified FINAL context.

This prevents serialized evidence from becoming authoritative merely because it claims `provider=sandcloud` or `provider=caser`.

## Required binding

A trusted execution receipt must match all of:

```text
provider
operation_id
pre_proof_digest
receipt_digest
receipt_id
status
subject_digest
evidence_digest
```

The execution trust verifier receives the exact `pre_proof_digest` from the structurally verified FINAL proof context. It never trusts a PRE digest only because it appears in provider-controlled evidence metadata.

## Fail-closed cases

The adapter or trust verifier rejects:

- wrong provider;
- operation transplant;
- PRE-proof transplant;
- malformed or recomputed receipt with stale digest;
- missing or invalid SHA-256 bindings;
- invalid execution time ordering;
- unknown status outside the canonical enum;
- external verifier false or exception;
- missing authoritative receipt in the trusted resolver;
- PRE-phase use of an execution trust verifier;
- envelope fields that do not reproduce from the authoritative receipt.

## Provider boundary

SandCloud and CASER do not currently expose a canonical repository-backed receipt API to OperationProof. R4 therefore defines a vendor-neutral receipt contract rather than inventing provider-specific wire formats. Provider-native receipts should be translated into this contract by a thin integration layer while their native signatures, attestations, or trusted receipt-store records remain the authenticity source.
