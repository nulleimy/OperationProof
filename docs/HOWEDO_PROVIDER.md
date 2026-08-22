# HOWEDO Continuity Provider

## Purpose

The HOWEDO adapter converts a HOWEDO `ContinuityWitness` into the canonical
OperationProof `continuity` evidence layer without importing or embedding the HOWEDO runtime.

## Input contract

The adapter accepts the canonical HOWEDO witness fields:

- `snapshot_id`
- `action`
- `reason_codes`
- `witness_digest`

Supported native actions are `CONTINUE`, `PAUSE`, `REVALIDATE`, `ABORT`, and `RECOVER`.

## Independent verification

Before emitting evidence, OperationProof independently recomputes the HOWEDO witness digest over:

```json
{
  "action": "CONTINUE",
  "reason_codes": ["..."],
  "snapshot_id": "sha256:..."
}
```

A malformed digest, unknown action, malformed snapshot identifier, or malformed reason set is rejected.

## Fail-closed mapping

| HOWEDO action | OperationProof verdict | Meaning |
| --- | --- | --- |
| `CONTINUE` | `PASS` | The original operation may proceed from a continuity perspective. |
| `PAUSE` | `FAIL` | Another control-flow step is required. |
| `REVALIDATE` | `FAIL` | Revalidation must complete before the original operation may proceed. |
| `ABORT` | `FAIL` | The operation must not proceed. |
| `RECOVER` | `FAIL` | Recovery is a separate operation; it does not authorize the original operation. |

`UNKNOWN`, unsupported, or malformed input never becomes `PASS`.

## Operation binding

HOWEDO's native witness binds continuity state to `snapshot_id`; it does not natively contain an
OperationProof `operation_id`. The adapter therefore creates a separate `subject_digest` binding
`operation_id` and `snapshot_id` and records this as `adapter-attached-operation-id` metadata.

This R2 adapter verifies content integrity, not provider identity or signature authenticity. Signed
provider attestations remain a later trust-layer concern and must not be inferred from a valid digest.

## Trust boundary

OperationProof does not own HOWEDO policy or continuity semantics. HOWEDO remains authoritative for
its native continuity decision. OperationProof only validates, normalizes, binds, and composes that
evidence with the other OperationProof layers.
