# HOWEDO Continuity Provider

## Purpose

The HOWEDO adapter converts a HOWEDO `ContinuityWitness` into the canonical OperationProof
`continuity` evidence layer without importing or embedding the HOWEDO runtime.

## Native witness contract

The adapter verifies the canonical HOWEDO witness fields:

- `snapshot_id`
- `action`
- `reason_codes`
- `witness_digest`

Supported native actions are `CONTINUE`, `PAUSE`, `REVALIDATE`, `ABORT`, and `RECOVER`.

OperationProof independently recomputes HOWEDO's witness digest over the canonical action,
reason codes, and snapshot identifier.

## Trusted operation binding

A native HOWEDO witness does **not** contain an OperationProof `operation_id` or trusted freshness
window. Therefore it is insufficient by itself to emit passing continuity evidence.

R2 requires a separate `operationproof.howedo-binding.v1` object containing:

- exact `operation_id`
- exact HOWEDO `snapshot_id`
- exact HOWEDO `witness_digest`
- provider-bound `issued_at`
- mandatory provider-bound `expires_at`
- deterministic `binding_digest`

The adapter also requires an external `binding_verifier`. This verifier represents the trusted
provider/attestation boundary and must establish authenticity of the binding through a mechanism
outside the OperationProof core, for example a verified provider response, signed attestation, or
trusted local mapping. A boolean `True` is required; verifier failure, exception, or absence fails closed.

The binding digest protects canonical content integrity but is **not** itself an authenticity proof.

## Anti-transplant invariant

OperationProof rejects a binding when its `operation_id`, `snapshot_id`, or `witness_digest` differs
from the operation and witness being adapted. A valid continuity witness therefore cannot be attached
by the adapter to an arbitrary second operation.

## Freshness invariant

`issued_at` and `expires_at` come exclusively from the externally verified binding. `expires_at` is
mandatory and must be later than `issued_at`. These provider-bound timestamps are copied into the
canonical `EvidenceEnvelope`, where normal OperationProof verification rejects expired evidence.

A caller-supplied timestamp that is not covered by the trusted binding cannot extend witness validity.

## Fail-closed mapping

| HOWEDO action | OperationProof verdict | Meaning |
| --- | --- | --- |
| `CONTINUE` | `PASS` | The exact bound operation may proceed from a continuity perspective. |
| `PAUSE` | `FAIL` | Another control-flow step is required. |
| `REVALIDATE` | `FAIL` | Revalidation must complete before the original operation may proceed. |
| `ABORT` | `FAIL` | The operation must not proceed. |
| `RECOVER` | `FAIL` | Recovery is a separate operation; it does not authorize the original operation. |

Unknown actions, malformed witnesses, invalid bindings, unverifiable bindings, missing expiry, or
provider-verifier errors never become `PASS`.

## Evidence binding

The canonical continuity evidence contains:

- a `subject_digest` over exact `operation_id + snapshot_id`
- an `evidence_digest` over exact `witness_digest + binding_digest`
- metadata identifying both HOWEDO witness and binding protocols

This means the OperationProof evidence record cryptographically commits to both the native continuity
witness and the separately trusted operation/freshness association.

## Trust boundary

HOWEDO remains authoritative for continuity semantics. OperationProof does not claim that a native
HOWEDO content digest proves provider identity. Authenticity of the operation binding remains the
responsibility of the supplied trusted verifier. OperationProof validates, normalizes, binds, and
composes the verified result with its other evidence layers.
