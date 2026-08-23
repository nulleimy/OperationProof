# V-One authorization provider boundary

OperationProof treats V-One as an external authorization authority. OperationProof does not reimplement V-One policy, approval, capability, revocation, precondition, grant-consumption, or dispatch logic.

## Canonical provider artifacts

The R5 adapter consumes V-One `execution-grant/v2` as authorization evidence for one OperationProof PRE operation.

`AuthorizationSnapshot` alone is intentionally insufficient for PASS. A `v-one-policy-decision/v1` outcome of `allow` is also insufficient. Only a current, exact, externally authenticated `execution-grant/v2` may map to OperationProof authorization PASS.

V-One durably consumes a `ONE_TIME` grant before dispatch. R5.1 additionally recognizes authoritative `grant-consumption-witness/v1` only for revalidating the already-authorized embedded PRE proof inside a FINAL proof.

These are deliberately different trust questions:

- **DIRECT PRE admission:** is this exact grant authentic, current, and still admissible/unused according to authoritative V-One state?
- **embedded PRE during FINAL verification:** was this exact grant durably consumed for this exact execution while the grant/evidence is still inside its lifetime?

A consumption witness never substitutes for DIRECT unused-grant admission and never extends authorization lifetime.

## Exact operation binding

R5 defines one explicit provider profile rule:

```text
OperationProof operation_id == V-One execution-grant/v2 execution_id
```

There is no alias, fallback, or caller-selected translation table. A different identity mapping requires a separately reviewed protocol.

## Grant requirements

The adapter and provider-trust verifier require:

- exact V-One `execution-grant/v2` field set
- exact integer `schema_version == 2` (bool/float lookalikes are rejected)
- `execution_id == OperationProof operation_id`
- `required_permission == execution.run`
- `use_semantics == ONE_TIME`
- supported V-One precondition enforcement class
- non-negative integer revocation epoch
- canonical UTC millisecond timestamps
- positive grant TTL no longer than 300 seconds
- precondition witness no more than 30 seconds before grant issuance
- `issued_at <= verification time < expires_at`
- valid provider-native lowercase 64-hex SHA-256 fields
- exact recomputation of V-One `grant_digest`
- an external trusted grant verifier returning true for DIRECT PRE admission

The adapter computes an additional OperationProof-local `sha256:` digest over the complete grant document. The V-One native digest remains content identity; neither digest is issuer authenticity by itself.

## Mutation / TOCTOU boundary

Provider documents are caller- or resolver-owned mutable mappings. R5/R5.1 deep-snapshot them through canonical JSON before validation and before crossing an external verifier boundary.

For grants:

1. the adapter/resolver result is detached into an OperationProof-owned snapshot;
2. structural, digest, freshness and binding validation runs on that snapshot;
3. the external admission verifier receives a separate detached copy;
4. normalized evidence is produced from the original validated snapshot.

For consumption witnesses the same rule applies: the resolver result is detached before validation and the external consumption verifier receives another detached copy.

Therefore callback mutation cannot alter the document that was validated or the evidence derived from it.

## Evidence mapping

The authorization envelope uses:

- layer: `authorization`
- provider: `vone`
- decision: `execution-grant/v2`
- verdict: `PASS`
- issued/expires: exact V-One grant window

The subject digest binds the operation to the snapshot, actor, workspace, environment, capability, capability definition, target, and payload. The evidence digest binds the provider, exact OperationProof grant-document digest, and V-One native grant digest.

## Trusted verification stage

The public `TrustVerificationContext` remains exactly the original six-field R3 dataclass. It has no stage field or property.

R5.1 keeps provider stage entirely private to OperationProof trust verification:

- `DIRECT` for normal PRE verification;
- `EMBEDDED_PRE_OF_FINAL` when the exact embedded PRE is recursively revalidated as part of FINAL verification.

The stage is held in a private `ContextVar` as a revocable invocation object. On verifier callback exit the object is marked inactive before the ContextVar is reset. If an `asyncio` child task inherited the ContextVar binding, it holds the same now-revoked object and therefore cannot retain embedded-FINAL authority after the callback ends.

Outside an active provider callback, stage resolution falls back to `DIRECT`. A direct call to the V-One verifier cannot manufacture `EMBEDDED_PRE_OF_FINAL`.

The R3/R3.1 context boundary remains unchanged: embedded PRE evidence is verified with the PRE proof's own phase, operation id, proof digest and `pre_proof_digest=None`.

## DIRECT PRE provider trust

`make_vone_execution_grant_trust_verifier()` re-resolves the exact grant out of band by its OperationProof document digest, snapshots it, validates it, reproduces the envelope, and invokes the external `grant_verifier` on a separate detached copy.

The deployment's `grant_verifier` must fail closed when the grant is consumed, revoked, invalidated, unauthenticated, or otherwise no longer admissible.

## Embedded PRE inside FINAL

A valid FINAL proof recursively revalidates its exact embedded PRE proof. At this point a legitimate ONE_TIME grant may already be consumed, so the unused-grant admission check is not reused.

R5.1 instead requires both `consumption_resolver` and `consumption_verifier`. The authoritative `grant-consumption-witness/v1` is resolved by grant JTI, snapshotted, structurally validated, digest-checked, binding-checked, then externally authenticated on a separate detached copy.

The witness must have the exact field contract and bind:

- exact integer `schema_version == 1`
- grant JTI and grant ID
- native grant digest
- execution ID / OperationProof operation ID
- authorization snapshot digest
- execution capsule digest
- runner class
- live revocation epoch equal to the grant epoch
- V-One conformance and clock witness digests
- canonical `consumed_at`
- `sqlite-begin-immediate/v1` serialization contract
- authority revision
- exact recomputed native witness digest

OperationProof additionally requires:

```text
issued_at <= consumed_at < expires_at
consumed_at <= verification_time < expires_at
```

A missing, malformed, mismatched, expired, future, false, throwing, or unauthenticated witness fails closed.

## Trust roots and non-goals

Resolver configuration plus the external admission and consumption verifiers are deployment trust roots. They must never be learned from the proof, grant, envelope, or witness itself.

OperationProof does not issue, revoke, consume, refresh, or dispatch V-One grants. It does not infer consumption from execution success. Serialized OperationProof evidence is never itself the authority source.
