# R5 source evidence

R5 hardens the existing V-One authorization provider adapter against the current V-One canonical contracts reviewed from `nulleimy/V-One@f9a4cc8e1568b25e381e3f3f009c0d5eba6a4879`.

Authoritative source contracts reviewed:

- `voodoo_product/authoritative_grant.py` — `execution-grant/v2`
- `voodoo_product/authorization_snapshot.py` — `authorization-snapshot/v1`
- `voodoo_product/policy_decision.py` — `v-one-policy-decision/v1`
- `voodoo_product/evidence_primitives.py` — provider canonical JSON hashing
- ADR-0009 — grant issuance/authenticity boundary
- ADR-0010 — immutable authorization snapshot boundary

R5 semantic decision:

- policy `allow` is not OperationProof authorization PASS
- authorization snapshot alone is not OperationProof authorization PASS
- only a current exact `execution-grant/v2`, externally authenticated/live-revalidated and exactly bound by `execution_id == operation_id`, may normalize to PASS
- native grant digest proves content identity, not issuer authenticity

Hardening added in this slice:

- canonical deep snapshot before external verifier callback
- verifier receives a separate detached grant copy
- callback/closure mutation cannot change normalized evidence
- future-issued grants fail closed
- exact V-One execution identity remains the OperationProof operation identity for the R5 profile
