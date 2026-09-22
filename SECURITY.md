# Security policy

hallpass makes authorization decisions, so security reports are taken seriously.

## Reporting a vulnerability

Please do not open a public issue. Report privately through
[GitHub security advisories](https://github.com/roee-hersh/hallpass/security/advisories/new).

Include the version or commit, the configuration involved (without secrets) and steps to reproduce.
You should get a first response within a few days.

## Scope

Of particular interest: any case where hallpass answers `allow` when the upstream system would not,
credential leakage, and bypasses of the API key check.
