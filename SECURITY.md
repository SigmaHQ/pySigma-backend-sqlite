# Security policy

Security fixes cover the latest released minor line and the development branch.

## Report a vulnerability

Open **Security → Advisories → Report a vulnerability** in
`wagga40/pySigma-backend-sqlite`. This is the private reporting inbox for the
backend, including copies installed from PyPI. Include
the backend version, SQLite version, affected output format and a minimal example with the
expected and observed behavior. Keep report details in the private advisory.
[Private reporting form](https://github.com/wagga40/pySigma-backend-sqlite/security/advisories/new)

We accept private reports about escaping failures that let rule values or field names
change generated SQL structure, unsafe conversion or runtime behavior, resource exhaustion,
and the build or release process. Pipelines, backend configuration containing SQL expressions,
and executable queries or correlation plans supplied by callers require a trusted source.
Ordinary detection mismatches can be reported in the issue tracker. Reports specific to the
core parser or modifier processing belong with pySigma.
[pySigma reporting policy](https://github.com/SigmaHQ/pySigma/security/policy)

Maintainers triage privately on a best-effort basis, coordinate fixes and disclosure with
affected projects, and offer credit to the reporter with their consent.
