# Trust Model

OperationProof trusts no provider merely because it is configured.

A provider claim is acceptable only when its adapter can produce a canonical `operationproof.evidence-envelope.v1` containing:

- exact operation identity;
- canonical layer identity;
- provider identity;
- native provider decision;
- normalized verdict (`PASS`, `FAIL`, `UNKNOWN`);
- digest of the subject checked;
- digest of the provider evidence;
- issue time and optional expiry.

## Fail-closed conditions

The verifier rejects or refuses to verify when it encounters:

- a missing required layer;
- `FAIL` or `UNKNOWN`;
- malformed or non-SHA-256 digests;
- duplicate canonical layers;
- evidence bound to another operation;
- expired evidence;
- a proof digest mismatch;
- a Final proof bound to an invalid, rejected, missing, or digest-mismatched Pre proof.

## Trust boundaries

Provider evidence remains authoritative only for the layer it owns. For example, HOWEDO continuity evidence cannot grant authorization, and an execution sandbox cannot self-authorize an operation.
