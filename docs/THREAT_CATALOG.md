# Threat & Quality Coverage Catalog

The following is the **target review taxonomy**, not a claim that the baseline CLI detects each item. A contextual AI review and/or specialized tooling is required for many categories.

| Domain | Checks and examples | Baseline CLI |
| --- | --- | --- |
| Secret management | Privileged API keys, DB URLs, credentials, client bundles, logs, key rotation | Partial heuristic |
| Supabase / DB exposure | RLS enablement, policies, grants, roles, security definer, exposed storage | Explicit RLS-disable marker only |
| Authentication | Password and session handling, OAuth/OIDC, MFA, token storage/revocation | Manual |
| Authorization | Object ownership (IDOR/BOLA), tenant isolation, role escalation (BFLA), policy enforcement | Manual |
| Injection | SQL/NoSQL/LDAP/command/template/HTML/OS injection, unsafe deserialization | Selected hotspots |
| Browser and APIs | XSS, CSRF, CORS, CSP, SSRF, open redirects, rate limits, uploads, cookie flags | Selected hotspots |
| Cryptography | Weak primitives, randomness, TLS verification, key lifecycle, encryption at rest | Selected hotspots |
| Privacy | Personal data minimization, retention, disclosure, insecure analytics/logs | Manual |
| Supply chain | Dependencies, CVEs, SBOM, pinned actions, artifacts, code provenance | External scanners |
| Infrastructure | IAM, containers, K8s, Terraform, DNS, cloud storage, network, secrets mounts | External scanners |
| Mobile | Android/iOS permissions, export, sandbox, keychain/keystore, WebView, secure storage | Specialist tooling |
| Desktop | Windows/macOS/Linux services, IPC, privilege boundaries, installers, signed updates | Specialist tooling |
| AI-integrated apps | Prompt injection, tool authorization, cross-tenant RAG leakage, model supply chain | Manual |
| Reliability | Error handling, resource exhaustion, concurrency, race conditions, availability | Manual |
| Quality and design | Logic bugs, architecture, performance, accessibility, maintainability, UX defects | Manual |
| CI/CD | GitHub Actions token scope, release signing, injection, self-hosted runner trust | Manual / external |

## Correctly interpreting the four public-post claims

1. **Exposed API keys:** distinguish frontend-safe publishable keys from *privileged* secrets. The former may be intended for public use and still require proper server-side permissions.
2. **Missing Supabase RLS:** verify table exposure/grants and policies in the actual DB, not a text-match only. RLS is not applicable to every database.
3. **Missing backend auth checks:** account for upstream middleware, API gateways and resource-level role checks.
4. **IDOR/BOLA:** a guessable ID or object URL is not enough; verify whether access is denied to a different authenticated user.

## Severity and status

- Severity: critical / high / medium / low / info; grounded in real impact, exploitation prerequisites and exposure.
- Confidence: high / medium / low, independent of severity.
- Status: observed / suspected / needs-validation / not-assessed / resolved.
- A scanner finding is a *signal* until validated. Every review needs an assessment coverage summary.
