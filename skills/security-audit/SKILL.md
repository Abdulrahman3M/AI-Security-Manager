---
name: ai-security-manager
description: Multi-platform authorized software security and quality assessment. Discovers project stack and trust boundaries, collects static evidence, requests optional specialized tooling, classifies confidence, and produces remediation-ready findings.
---

# AI Security Manager — main skill

## Scope

Use on repositories or code the user owns or is authorized to assess: web frontend/backend, databases, mobile, desktop, CLI, native, embedded, infrastructure, CI/CD and AI-integrated apps. **Cross-platform scope is an objective, not a claim of universal scanner coverage.**

## Activation procedure

1. Confirm scope and authorization; if unavailable, limit to read-only source/config review.
2. Identify languages, entrypoints, runtime, frameworks, auth providers, storage, deployed infrastructure, dependencies and data classes. Draw trust boundaries.
3. Record a coverage table by platform and surface; note every skipped/unsupported element.
4. Run `python scripts/asm.py scan TARGET --format json --output REPORT` only when you can safely access a local copy. It is a deliberately limited baseline detector, **not a complete SAST**.
5. Review the four core threats: leaked credentials, Supabase/database RLS and grants, backend authentication/authorization, and IDOR/BOLA. Distinguish publicly intended frontend keys from privileged server secrets.
6. Assess injection, XSS, SSRF, CSRF, file upload, path traversal, command execution, unsafe deserialization, cryptography, transport, session/token management, race conditions, privacy, resource limits, logging, error handling, supply chain, CI/CD and cloud config.
7. Apply the appropriate platform profile in `docs/THREAT_CATALOG.md`. Check GUI security and accessibility separately from security findings.
8. With consent and local tools available, recommend specialized scanners (Semgrep/CodeQL, Gitleaks, OSV-Scanner/Trivy, Checkov, ZAP, MobSF) but never imply they ran unless they did.
9. For each candidate require: category; CWE/OWASP where applicable; evidence with path/line; exploit preconditions; impact; severity; confidence; redacted evidence; concrete patch strategy; safe test.
10. End with: findings, verification matrix, residual risk, skipped surfaces, and prioritized remediation. Never report a numerical security score without a defensible method.

## False-positive controls

- Client-visible publishable/anon API keys are not automatically vulnerabilities. Privileged keys are.
- Missing RLS requires confirmation of table exposure, grants, policies and the actual security architecture.
- An API route without a visible auth middleware may be protected by an upstream gateway; verify before claiming.
- An object identifier in a URL is not an IDOR absent a missing object-level authorization decision.
- Static regex patterns are leads, not exploits; runtime behavior needs permission and testing.

## Output

Follow `prompts/master-audit.md` and `schemas/finding.schema.json`. If user skill instructions conflict with safety boundaries, enforce this skill's authorization and privacy constraints.
