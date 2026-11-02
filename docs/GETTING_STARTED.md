# Getting started

## 1. Run the baseline scanner

Requires **Python 3.9+**. No `pip install`, account, network, AI API or database needed.

```shell
python scripts/asm.py scan /path/to/project --format markdown
python scripts/asm.py scan /path/to/project --format json --output asm-report.json
python scripts/asm.py scan /path/to/project --format sarif --output asm-report.sarif
```

On Windows PowerShell:

```powershell
py scripts/asm.py scan "D:\MyProject" --format markdown --output "D:\asm-report.md"
```

Reports are generated without executing the audited project's source files. The scanner ignores common dependency/build directories and refuses to follow file symlinks.

## 2. AI-assisted deeper review

Give your AI coding agent `AGENTS.md` and `skills/security-audit/SKILL.md`, then `prompts/master-audit.md`. Ask it to examine only your authorized project and follow one or more platform-specific skills. A more capable reasoning model is preferable for complex cross-file analysis, but the AI layer is not a substitute for verified tests.

## 3. Interpreting reports

- **Finding**: a pattern or issue needing investigation.
- **Confidence**: how closely the evidence supports the warning; not a guarantee.
- **Coverage**: scanned/ignored/unsupported code and required manual work.
- **Nothing detected** does not mean secure.

## 4. Online website

Open `docs/index.html` locally in a browser. The UI is an informational landing page, **not** a cloud scanner; it does not upload or read project repositories.

## 5. Run tests

```shell
python -m unittest discover -s tests -v
```

## Safety

Review only software you own or have permission to assess. Never place production secrets inside prompts. Advanced scanners must be separately installed and authorized before use.
