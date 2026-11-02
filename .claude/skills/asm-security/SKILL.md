---
name: asm-security
description: Review authorized software projects for security weaknesses, privacy and quality risks, with evidence, confidence and remediation guidance.
---

# AI Security Manager

On invocation, first read the root `AGENTS.md`, `skills/security-audit/SKILL.md`, `prompts/master-audit.md`, `docs/THREAT_CATALOG.md` and the relevant specialist `skills/review-*/SKILL.md` files.

Proceed read-only and do not run audited project code. Do not move secret values into messages or logs. Use the local scanner only if a suitable tool environment and explicit scope are available; its findings are pattern-based leads, not proven vulnerabilities. Distinguish confirmed from needs-validation and report coverage gaps. Provide prioritized fixes and regression tests.

This skill expects the entire ASM repository to be present; see `docs/INTEGRATIONS.md` for usage in another project.
