---
name: asm-review-web
description: Frontend, backend, API and database security review profile.
---

# Web / API / Database profile

Use after the main security-audit skill. Trace request -> middleware -> handler -> service -> data access -> response; identify how identity and tenant ownership are enforced at *every* protected operation.

Check OWASP Top 10:2025 and API Security Top 10:2023; test for BOLA/IDOR and BFLA conceptually, horizontal/vertical access control, server-only secrets, SSRF, injection, XSS, CSRF, cookie flags, CORS, CSP, HTTP headers, upload security, webhook signatures, rate limits, and exposure of stack traces.

For Supabase: inventory tables, schemas, publication/API exposure, grants, RLS enabled/forced, restrictive/permissive policies, `auth.uid()` and tenant predicates, SECURITY DEFINER functions, service-role bypass and storage bucket rules. A `publishable`/legacy `anon` key alone is not a secret. Do not infer an actual database leak solely from missing policy text.

For SQLite: validate query parameterization, filesystem isolation, ownership checks and safe backups; RLS is not a SQLite feature. Mark tests requiring credentials or a running environment as NOT ASSESSED.
