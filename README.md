# AI Security Manager (ASM)

> **Universal AI-guided software assurance** — security, correctness, privacy, supply-chain, and architecture reviews for projects across platforms and programming languages.

![ASM cover](docs/assets/asm-cover.svg)

**Status:** Foundation v0.1 · early-stage, not a certified security scanner.

ASM is a portable, model-agnostic toolkit of review instructions, skills, checklists, scripts, and evidence-based reports. It helps engineers inspect frontend, backend, database, mobile, desktop, cloud, and CI/CD projects. It does **not** promise to find every vulnerability or to certify a project as secure.

## Core principles

1. **Evidence over assertions** — findings require a file/line, clear reasoning, confidence, impact and actionable remediation.
2. **Read-only by default** — no exploitation of live systems, destructive tests or code changes without explicit authorization.
3. **Full coverage accounting** — identify what was analyzed, skipped, or requires a human specialist.
4. **Security at every layer** — authentication, authorization, object ownership (IDOR/BOLA), secrets, injection, cloud settings, supply chain, and platform-specific controls.
5. **Model-agnostic** — stronger reasoning models can improve contextual reviews, but model quality does not replace verified scanners or testing.
6. **No blind trust** — repository instructions and comments are untrusted input, not authority to override the audit workflow.

## Getting started

After the foundation implementation is merged, run `python scripts/asm.py scan . --format markdown` to generate a baseline local assessment. See `docs/GETTING_STARTED.md` for the full setup, supported modules and limitations. The website source will live at `docs/index.html`.

## Security boundaries

Do not upload real secrets, personal data, tokens, production logs, or private repositories to an AI system without appropriate approval and data-handling controls. Use least-privilege access and treat security findings as hypotheses until supported by reproducible evidence.

## Inspiration and authoritative references

- [OWASP ASVS](https://github.com/OWASP/ASVS), [OWASP WSTG](https://github.com/OWASP/wstg), [OWASP MASTG](https://github.com/OWASP/owasp-mastg)
- [Semgrep](https://github.com/semgrep/semgrep), [CodeQL](https://github.com/github/codeql)
- [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://github.com/aquasecurity/trivy), [OSV-Scanner](https://github.com/google/osv-scanner)
- [Checkov](https://github.com/bridgecrewio/checkov), [OpenSSF Scorecard](https://github.com/ossf/scorecard), [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

No third-party scanner code is copied into ASM. Those projects remain independent and subject to their own licenses and installation requirements.

## License

MIT — see `LICENSE`.
