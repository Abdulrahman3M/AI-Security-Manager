# Integrating ASM with AI coding agents

ASM is primarily a **portable toolkit** plus an optional local scanner. It is **not** a native marketplace plugin for every agent, nor is it an autonomous exploitation platform.

## Run it without an AI account

Clone ASM and run:

```bash
python scripts/asm.py scan /path/to/authorized/project --format markdown
```

No network access, package installs or AI credentials are required for this command.

## Use with agents

| Host | Entry point included | How to use |
| --- | --- | --- |
| Cursor | `.cursor/rules/asm-security.mdc` | Open the ASM workspace and request an authorized audit; the relevance-based project rule can activate. |
| GitHub Copilot / VS Code | `.github/prompts/asm-security-audit.prompt.md` | Run/select the repository prompt file in an IDE that supports prompt files. |
| Claude Code | `.claude/skills/asm-security/SKILL.md` | Invoke `/asm-security` from the ASM workspace. |
| Gemini CLI | `GEMINI.md` | Work in the ASM workspace and explicitly ask for the audit. |
| General agents / Codex | `AGENTS.md` | Read root instructions, then master audit skill and relevant profile. |

### Audit another repository

Safest starting approach: open ASM and the authorized target repository in a **single local workspace** or provide the agent the local path to the target. Keep ASM's instructions and scan scripts in their original directories so all relative links work.

If embedding ASM inside another project, place its full contents under a dedicated folder (for example `tools/asm/`) and update any host instruction file's referenced paths accordingly. Do not copy only a short rule and expect the full analysis playbook to be present.

The agents are not equivalent: they differ in file access, command permissions, context budgets, skill activation and available models. The user remains responsible for approving any execution, secret sharing or deployment access.

## Strongest model advice

Choose the strongest reasoning model available for cross-file dataflow, multi-tenant authorization and architectural analysis. However, quality depends on available source, tools, verification and specialist review as well as model strength. A premium model alone does not make an assessment exhaustive.

## External scanners (not bundled)

Consider Gitleaks for secrets, Semgrep/CodeQL for source analysis, Trivy/OSV for dependencies, Checkov for IaC, OWASP ZAP for permitted web runtime tests, and MobSF for mobile. Verify licenses, installation integrity, support and tool-specific approval before running.

## When a report says NOT ASSESSED

If a technology cannot be interpreted safely or a relevant execution environment is not available, record a gap instead of a passing result.
