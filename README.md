# secure-prompt-masker

Mask sensitive text locally before using logs, prompts, request snippets, or copied troubleshooting data with AI-assisted tools.

## Why This Exists

Security and engineering workflows often require sharing text with an assistant, ticket, report, or teammate. That text can accidentally include authorization headers, cookies, tokens, account identifiers, contact details, internal project names, or customer-specific context.

`secure-prompt-masker` is a small local desktop utility that helps review and mask that text before it is copied elsewhere.

## What It Does

- Runs as a local Python/Tkinter desktop app.
- Masks common sensitive patterns such as tokens, cookies, authorization headers, credential-like key-value pairs, and phone-like values.
- Supports user-defined keywords for project-specific placeholders.
- Provides a URL encoding mode for copied request fragments.
- Keeps local preferences in ignored runtime files.
- Uses fake demo values only in repository examples.

## Quick Start

Requirements:

- Python 3.10 or newer
- Tkinter support in your Python installation

Run from the repository root:

```bash
python masking_app.py
```

Basic workflow:

1. Paste text into the input area.
2. Review the detected sensitive values.
3. Choose the values or categories to mask.
4. Copy the masked output only after manual review.

## Safe Demo Input

```text
POST /api/demo/action
Authorization: Bearer demo-token-value
Cookie: session=demo-session-value
X-Api-Key: demo-api-key-value
project=example-project
owner=sample-contact
message=Mask before using this text in an AI-assisted workflow.
```

Expected style of output:

```text
POST /api/demo/action
Authorization: Bearer ****************
Cookie: session=******************
X-Api-Key: ******************
project=***************
owner=**************
message=Mask before using this text in an AI-assisted workflow.
```

All values above are fake. Do not add real company names, customer data, credentials, domains, phone numbers, addresses, production logs, or private prompts to this repository.

## Verification

Run a basic syntax check:

```bash
python -m py_compile masking_app.py
```

Recommended manual smoke test:

1. Start the app.
2. Paste the fake sample above.
3. Run masking.
4. Confirm fake token, cookie, API key, and custom keyword values are masked.
5. Close the app and confirm no local runtime output is committed.

## Privacy And Security Notes

- Processing is intended to happen locally.
- Masked output can still contain sensitive context; review it before sharing.
- Clipboard contents may be visible to other local software.
- Local settings, captures, exports, logs, and screenshots should not be committed.
- Pattern-based masking is a safety aid, not a guarantee.

## Limitations

- Unusual secret formats may not be detected.
- Some benign identifiers may be masked as false positives.
- The tool does not replace secure handling procedures, DLP review, or legal/compliance approval.
- Public release requires both working-tree and Git-history scans.

## Documentation

- [Usage Guide](docs/USAGE.md)
- [Sample Data](docs/SAMPLES.md)
- [Privacy And Security](docs/PRIVACY_AND_SECURITY.md)
- [Public Release Checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Security Policy](SECURITY.md)

## License

No license has been selected yet.
