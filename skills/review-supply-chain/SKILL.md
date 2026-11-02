---
name: asm-review-supply-chain
description: Review dependencies, build workflows, containers, cloud and infrastructure as code.
---

# Supply-chain / Infra profile

Inventory lockfiles, packages, transitive dependencies, pinned GitHub Actions, integrity hashes, build scripts, release signing, artifacts, provenance and CI permissions. Check third-party actions, workflow injection, pull-request trust and token scope.

Review Dockerfiles and Kubernetes for least privilege, base-image provenance, secret mounts, capabilities, privileged containers, network exposure and resource limits. Review Terraform, cloud IAM and storage access policies.

Use specialized dependency and IaC scanners if installed and approved; never guess CVEs from a package name or assume the latest dependency is secure. Map relevant findings to NIST SSDF, OpenSSF and OWASP supply-chain risks.
