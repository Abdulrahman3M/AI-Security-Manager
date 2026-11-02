# Security policy

AI Security Manager is a **development-stage defensive toolkit**. Findings from its baseline scanner are unverified leads. Do not use it as evidence of compliance, a penetration-test certificate or a security guarantee.

## Reporting a vulnerability in ASM

Please report security issues privately using GitHub's private vulnerability reporting feature when available. Otherwise contact a maintainer through a private channel before disclosing exploit details publicly. Do not open public issues containing credentials or live exploit payloads.

## Safe defaults

- No execution of the audited project's source code.
- No network requests from the scanner.
- No automatic changes to audited projects.
- No raw matched secrets in report output.
- File symlinks skipped; common build/dependency directories excluded; 2 MB/file and 50,000 discovered file caps.
- JSON, Markdown and SARIF output should be reviewed before redistribution because paths and filenames may still reveal project structure.

## Unsupported assurances

The scanner does not perform DAST, full semantic dataflow analysis, binary reverse engineering, authorization exploit verification or vulnerability-advisory lookups. Human review and specialist tools remain necessary.
