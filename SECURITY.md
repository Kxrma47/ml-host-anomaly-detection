# Security Policy

## Supported version

Security fixes are applied to the latest release on the `main` branch.

## Reporting a vulnerability

Do not publish credentials, private telemetry, exploit details or personal data
in a public issue. Use GitHub's private vulnerability reporting feature for this
repository. Include the affected version, reproduction conditions, impact and a
minimal proof of concept that does not contain real secrets.

The project maintainers should acknowledge a report, reproduce it, assess
severity, prepare tests and a fix, and coordinate disclosure. No response-time
or remediation-time guarantee is made for this research project.

## Safe deployment

- Run the collector as a dedicated least-privileged account.
- Grant explicit read access only to required event sources.
- Keep telemetry, state, models and reports owner-readable only.
- Use encrypted storage and an approved retention/deletion policy.
- Verify dataset provenance before training and rerun the standards gate before release.
- Do not add keylogging, password capture, browser form capture or TLS interception.

