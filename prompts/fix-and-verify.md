# Remediation and Verification Prompt

For each evidence-backed finding:

- Explain the root cause and affected trust boundary in plain language.
- Propose the **smallest secure change** and alternative where tradeoffs matter.
- Preserve current behavior and backward compatibility where safe; identify migration concerns.
- Add a negative test that demonstrates the denied unauthorized operation, plus a positive test for authorized operation.
- For IDOR/BOLA: validate on the server that current user may access **this object**; test two different identities and two tenant contexts.
- For Supabase: demonstrate select/insert/update/delete policies and grants per role, test anon/authenticated/service role assumptions, and ensure `service_role` is never embedded in browser-delivered code.
- For leaked secrets: revoke/rotate compromised credentials and investigate historical exposure; merely deleting code is insufficient.
- Output proposed diffs and test plans, **not automatic commits**, unless explicitly asked.
- Mark untested changes clearly, and recommend an independent final check.
