# Security policy

## Supported versions

Security fixes are applied to the latest code on the default branch. Until versioned releases are published, older snapshots are not supported.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's GitHub security-advisory reporting feature. Do not include hostnames, account names, production policy exports, ETL files, credentials, or other sensitive evidence in a public issue.

If private vulnerability reporting is not enabled, open a minimal public issue asking the maintainer for a private contact channel. Do not disclose exploit details in that issue.

## Operational incidents

This project can change Defender exclusions and Windows Firewall rules when explicitly invoked. A failed or interrupted control test is an operational cleanup issue, not necessarily a product vulnerability. Preserve the command output and run/test ID, follow the documented cleanup procedure, and use your organization's incident process for any unauthorized change.
