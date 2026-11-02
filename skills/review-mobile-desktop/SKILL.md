---
name: asm-review-mobile-desktop
description: Native mobile and desktop software security profile.
---

# Native / Mobile / Desktop profile

**Android:** exported components, intents, permissions, WebView interfaces, cleartext network config, backups, signing, keystore usage, hardcoded secrets, local storage, certificate handling, update integrity. Map to OWASP MASVS/MASTG.

**iOS / macOS:** entitlements, ATS, keychain, sandbox boundaries, URL schemes, local data encryption, IPC, code signing, notarization, update channel and native bridge.

**Windows / Linux desktop:** filesystem permissions, shell invocation and command injection, insecure DLL or library loading, registry/services, update signatures, privileged helper design, process isolation, credential storage and installer behavior.

**Electron / Tauri / cross-platform:** web-to-native IPC, contextIsolation, nodeIntegration, preload API exposure, CSP, remote content, protocol handlers and updater trust.

For binaries or runtime-only bugs, static source review is insufficient: request separate permission and specialist tooling. Never execute untrusted apps during a baseline audit.
