# Security Policy

## Scope

This repository is a local masking utility for security portfolio use. Reports should focus on issues that could cause sensitive text to be exposed, persisted, or documented unsafely.

## Do Not Include Raw Secrets

When reporting a problem, do not include raw credentials, tokens, cookies, private prompts, personal data, customer names, or production logs.

Use this format instead:

```text
file: path/to/file
line: line number when available
commit: short commit hash when relevant
risk: short reason
value: redacted
```

## Safe Test Data

Use fake placeholders only:

```text
example-company
example-project
demo-token-value
sample-contact
demo-address
```

## Release Requirement

Before this repository is treated as public-ready, the current working tree and full public branch history must be scanned for removed real-world default keywords and other sensitive data.
