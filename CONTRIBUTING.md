# Contributing to OperationProof

Thank you for helping improve OperationProof. Keep changes focused, reviewable, tested, and reversible.

## Workflow

1. Open or reference an issue for material behavior changes.
2. Create a focused branch from the repository's default branch.
3. Make the smallest complete change that solves the stated problem.
4. Add or update tests and documentation.
5. Run the repository's documented verification commands.
6. Open a pull request and include risk, evidence, and rollback notes.

## Pull request standard

A pull request must state:

- what changed and why;
- what was intentionally left out;
- verification commands and results;
- security, compatibility, data, and operational risks;
- rollback or safe-disable procedure.

Do not commit secrets, personal data, generated runtime state, local databases, or unverifiable claims. A green check proves only the scope exercised by that check.

## Governance

Maintainer review is required. Security-sensitive, release, authorization, persistence, billing, and production-effect changes require explicit owner approval and must fail closed when required evidence is missing.
