# Roadmap — trustworthy scope first

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0 | Research, threat taxonomy, skills, safety contract, architecture | Foundation |
| 1 | Local stdlib scanner, evidence records, JSON/Markdown/SARIF, tests | Foundation |
| 2 | Opt-in scanner adapters (Gitleaks, Semgrep, OSV/Trivy, Checkov) | Planned |
| 3 | Full auth/tenant/RLS review templates and safe verification harnesses | Planned |
| 4 | AI-guided multi-pass triage, deduplication, remediation PR workflow | Planned |
| 5 | Native/mobile/desktop sandbox integrations and binary instrumentation | Planned |
| 6 | Enterprise integrations, policy-as-code and repeatable assurance gates | Planned |

### Definition of done for a real finding

Explicit affected asset, stable ID, evidence path/line, impact, prerequisites, reproducibility, severity, confidence, remediation, verification test and status.

### Definition of done for scan

Every scan records scope, tool versions, files scanned/skipped and inaccessible platforms. No promise of 100% security. No tool silently executes target code.
