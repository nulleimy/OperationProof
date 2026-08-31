# Security Policy

## Supported scope

Security fixes are maintained on the current default branch while OperationProof remains pre-release. Repository visibility or a passing CI run is not a production-readiness guarantee.

## Reporting a vulnerability

Do not disclose vulnerabilities, credentials, personal data, private URLs, or exploit details in public issues or pull requests. Use GitHub private vulnerability reporting when enabled. If it is unavailable, open a public issue requesting a private contact without including sensitive details.

Include the affected revision, component, prerequisites, minimal reproduction, impact, expected safe behavior, and a suggested mitigation when known.

## Security baseline

- never commit credentials or production data;
- keep privileged decisions and authorization server-side;
- apply least privilege and deny-by-default behavior;
- validate untrusted input and bound resource use;
- preserve auditable evidence without logging secrets;
- treat missing or unverifiable security evidence as a failure, not success;
- rotate exposed credentials even if the committed file is later removed.

No response-time or remediation SLA is promised while the project remains pre-release.
