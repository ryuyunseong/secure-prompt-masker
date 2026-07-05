# Usage Guide

## Run The App

From the repository root:

```bash
python masking_app.py
```

The application starts as a local desktop window.

## Basic Workflow

1. Paste text into the input area.
2. Review or adjust the keyword list.
3. Choose masking mode.
4. Run the transform action.
5. Review the output before copying it to another tool.

## Custom Keywords

Use custom keywords for project-specific placeholder values that should always be masked. Keep these values fake when committing examples or screenshots.

Good public examples:

```text
example-company
example-project
internal-id-0000
sample-contact
demo-address
```

Do not commit real organization names, personal names, addresses, phone numbers, registration numbers, account IDs, API keys, session values, or customer-specific terms.

## Local Files

The app may create local runtime state such as:

```text
settings.json
```

This file is ignored by Git because it may reflect local preferences or user-entered keyword choices.

## Verification

Basic syntax check:

```bash
python -m py_compile masking_app.py
```

Manual smoke test:

1. Start the app.
2. Paste the fake sample from `docs/SAMPLES.md`.
3. Run masking.
4. Confirm obvious fake token and cookie values are masked.
5. Close the app without committing local runtime files.
