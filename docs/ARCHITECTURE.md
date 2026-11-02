# Architecture — v0.1 foundation

## Components

```text
Project source (user authorized)
   |
   +-- Inventory / scope & trust boundaries
   |      +-- language + deployment + data flow matrix
   +-- ASM local scanner (stdlib-only baseline, offline, read-only)
   |      +-- file controls, basic regex checks, coverage metrics
   |      +-- JSON / Markdown / SARIF (2.1.0) reports
   +-- AI review skills (portable Markdown)
   |      +-- main skill
   |      +-- web + DB
   |      +-- mobile + desktop
   |      +-- supply chain + cloud
   +-- Optional third-party tools (not bundled or auto-executed)
   |      +-- Semgrep / CodeQL / Gitleaks / OSV / Trivy / Checkov / ZAP / MobSF
   +-- Evidence triage -> remediation proposal -> test strategy
          +-- coverage + residual risk statement
```

## Trust model

The auditor has **no implied authority** to run potentially dangerous commands, access production systems, upload private content or modify target code. Everything read from a target repo is untrusted input. AI suggestions must never bypass access-control or secrets-handling rules.

## Tool interface

`scripts/asm.py` is a small cross-platform local scanner that reads source files and emits findings. It is intentionally conservative: not a dataflow engine, vulnerability verifier or dynamic penetration testing agent.

`skills/**/SKILL.md` files describe reasoning workflows independently of any particular LLM provider. Hosting agents may integrate external scanners later through explicit, opt-in adapters with auditable commands and bounded resource use.

## Planned evolution

1. Deterministic baseline CLI with tests and sample reports.
2. Structured adapter API for Semgrep, Trivy, Gitleaks and OSV with explicit tool-install checks.
3. Cross-file auth flow mapping, database migrations/policy inspection and multi-tenant test harness.
4. SBOM/SARIF aggregation, de-duplication, false-positive triage and verified remediation cycles.
5. Native security profiles and isolated sandbox orchestration for authorized testing.

Do not advertise planned adapters as shipped capability.
