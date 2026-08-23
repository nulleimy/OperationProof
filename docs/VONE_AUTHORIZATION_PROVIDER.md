# V-One authorization provider boundary

OperationProof treats V-One as an external authorization authority. OperationProof does not reimplement V-One policy, approval, capability, revocation, precondition, or grant-consumption logic.

## Canonical provider artifact

The R5 adapter consumes V-One `execution-grant/v2` as authorization evidence for one OperationProof PRE operation.

`AuthorizationSnapshot` alone is intentionally insufficient for a PASS. V-One documents the snapshot as immutable authorization evidence rather than an irrevocable bearer permission, and authoritative grant issuance re-checks live permission and deny gates. The grant therefore supplies the current, narrowed, short-lived authority artifact.

A `v-one-policy-decision/v1` outcome of `allow` is also insufficient for OperationProof authorization PASS. Policy evaluation is an input to V-One authority; it is not the final execution authority artifact.

## Exact operation binding

R5 defines one explicit provider profile rule:

```text
OperationProof operation_id == V-One execution-grant/v2 execution_id
```

There is no alias, fallback, or caller-selected translation table in R5. A deployment that needs a different identity mapping requires a separately reviewed binding protocol rather than weakening this equality rule.

## Required bindings

The adapter requires:

- exact V-One `execution-grant/v2` field set
- `execution_id == OperationProof operation_id`
- `required_permission == execution.run`
- `use_semantics == ONE_TIME`
- supported V-One precondition enforcement class
- non-negative revocation epoch
- canonical UTC millisecond timestamps
- positive grant TTL no longer than 300 seconds
- precondition witness no more than 30 seconds before grant issuance
- `issued_at <= verification time < expires_at`
- valid provider-native lowercase 64-hex SHA-256 fields
- exact recomputation of V-One `grant_digest`
- an external trusted grant verifier returning true

The adapter computes an additional OperationProof-local `sha256:` digest over the complete grant document. The V-One native digest remains provider evidence; neither digest is an authenticity root by itself.

## Mutation / TOCTOU boundary

Provider documents are caller-owned mutable mappings. R5 deep-snapshots the complete grant through canonical JSON before validation and normalization.

The external grant verifier receives a separate detached copy. Mutation by the verifier callback, or mutation of the caller-owned grant through a closure while the verifier runs, cannot change the already validated adapter-owned snapshot.

This preserves the invariant:

```text
exact grant validated
== exact grant normalized
== exact grant represented by grant_document_digest
```

## Evidence mapping

The resulting envelope uses:

- layer: `authorization`
- provider: `vone`
- decision: `execution-grant/v2`
- verdict: `PASS`
- issued/expires: exact V-One grant window

The subject digest binds the operation to the snapshot, actor, workspace, environment, capability, capability definition, target, and payload. The evidence digest binds the provider, exact OperationProof grant-document digest, and V-One native grant digest.

## Provider trust

`make_vone_execution_grant_trust_verifier()` is intended for the R3 `ProviderTrustRegistry`.

It fails closed unless:

- verification occurs in PRE root/evidence context
- `pre_proof_digest` is absent
- the envelope operation matches the trusted context operation
- the serialized envelope and metadata use the exact bounded contract
- the authoritative grant can be re-resolved out of band by its OperationProof document digest
- the authoritative grant passes structural, freshness, native-digest, and external authority verification again
- reproducing the authorization envelope from that authoritative grant yields the exact serialized envelope

Resolver configuration and the external grant verifier are deployment trust roots. They must never be learned from the proof, grant, or envelope.

## External verifier responsibility

The external V-One grant verifier must authenticate and live-revalidate the provider artifact according to deployment policy. That includes any V-One state not self-authenticating from the serialized grant, such as current revocation/consumption/issuer authority where applicable.

A native `grant_digest` is content integrity, not issuer authenticity. If the deployment uses V-One signed grant envelopes or another authenticated issuer boundary, signature/key/trust-policy verification belongs inside this external verifier.

OperationProof does not issue, revoke, consume, refresh, or broaden V-One grants.
