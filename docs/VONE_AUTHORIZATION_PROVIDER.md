# V-One authorization provider boundary

OperationProof treats V-One as an external authorization authority. OperationProof does not reimplement V-One policy, approval, capability, revocation, precondition, or grant-consumption logic.

## Canonical provider artifact

The R5 adapter consumes V-One `execution-grant/v2` as authorization evidence for one OperationProof PRE operation.

`AuthorizationSnapshot` alone is intentionally insufficient for a PASS. V-One documents the snapshot as immutable authorization evidence rather than an irrevocable bearer permission, and authoritative grant issuance re-checks live permission and deny gates. The grant therefore supplies the current, narrowed, short-lived authority artifact.

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
- grant not expired at verification time
- valid provider-native lowercase 64-hex SHA-256 fields
- exact recomputation of V-One `grant_digest`
- an external trusted grant verifier returning true

The adapter computes an additional OperationProof-local `sha256:` digest over the complete grant document. The V-One native digest remains provider evidence; neither digest is an authenticity root by itself.

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

OperationProof does not issue, revoke, consume, or refresh V-One grants.
