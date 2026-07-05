# Privacy And Security

## Local Processing

`secure-prompt-masker` is designed as a local desktop utility. It does not require a hosted backend service for masking.

## Data Handling Expectations

- Treat all pasted text as potentially sensitive.
- Review masked output before sharing it with any external service.
- Do not commit local settings, logs, screenshots, exports, or copied customer text.
- Do not use real secrets to demonstrate the app.

## Clipboard Risk

The app can copy output to the operating system clipboard. Clipboard data may be readable by other local applications, remote desktop tools, or clipboard managers. Clear the clipboard when handling sensitive material.

## Git History Risk

Removing sensitive text from the current file is not enough if the repository is public or will become public. Review the full Git history before release.

Recommended checks:

```bash
git grep -n -I "sensitive-placeholder"
git log --all --oneline
git rev-list --all
```

Use targeted searches for known values without printing the values in reports.

## Reporting Issues

If you find real sensitive data in this repository, report the file path, line number, commit hash when relevant, and risk reason. Do not include the raw sensitive value in the report.
