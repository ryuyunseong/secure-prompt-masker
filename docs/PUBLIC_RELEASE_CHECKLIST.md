# Public Release Checklist

Use this checklist before treating the repository as portfolio-ready.

## Required

- README explains purpose, usage, privacy notes, and limitations.
- Samples use fake values only.
- No real organization names, personal names, addresses, registration numbers, phone numbers, emails, domains, credentials, cookies, or customer terms in the working tree.
- `.gitignore` blocks local settings, logs, captures, exports, screenshots, and temporary files.
- `python -m py_compile masking_app.py` passes.
- Manual GUI smoke test passes.
- Git history scan finds no sensitive values.
- Repository license decision is explicit.

## Git History Requirement

The public branch history must not contain removed real-world default keywords or other sensitive values. If history has been rewritten, verify the result from a fresh clone before treating the repository as portfolio-ready.

## Manual GitHub Steps After Cleanup

1. Confirm the default branch contains only sanitized files.
2. Confirm full Git history scan is clean from a fresh clone.
3. Enable repository security features where available.
4. Add a concise repository description.
5. Pin the repository only after the public checklist passes.
