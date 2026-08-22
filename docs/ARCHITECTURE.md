# Architecture

```text
Agent / Runtime
      |
      v
OperationProof sidecar / library / gateway
      |
      +-- identity provider      (SPIFFE/OIDC/generic)
      +-- authorization provider (V-One/AGT/OPA/generic)
      +-- intent provider         (VOODOO Intent/generic)
      +-- continuity provider     (HOWEDO/generic)
      +-- tool-safety provider    (AGT/OPA/generic)
      +-- data-flow provider      (Presidio/policy/generic)
      +-- resource provider       (gateway/budget/generic)
      +-- execution provider      (SandCloud/CASER/generic)
      |
      +--> PreOperationProof --> execution --> FinalOperationProof
```

OperationProof is a connector and verifier, not a replacement for provider systems.

## Deployment modes

- **Library**: embedded SDK for local processes.
- **Sidecar**: one runtime communicates with a colocated OperationProof service.
- **Gateway**: multiple runtimes use one governed OperationProof service.

R0-R1 implements the pure core only. Network APIs and concrete provider adapters are later slices.

## Cross-cutting integrations

Observability, provenance, and assurance are intentionally not canonical gates. They can attach evidence and attestations without changing the eight-layer decision contract.
