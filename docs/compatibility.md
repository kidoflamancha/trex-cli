# Compatibility policy

This is the public compatibility contract for `1.0.0` and later 1.x releases.

## Versioned surfaces

| Surface | Current identifier | Compatibility rule at 1.0 |
|---|---|---|
| HTTP control plane | `/v1` | Existing operations, status semantics, and required fields remain compatible throughout 1.x. |
| Executable Job documents | `trex.example.io/v1` | Field meaning does not change; additions are optional or defaulted. |
| Catalog resources | `trex.example.io/catalog/v1` | Existing kinds and field meaning remain compatible throughout 1.x; additions are optional or defaulted. |
| Immutable Test Plans | `trex.example.io/test-plan/v1` | Existing intents and field meaning remain compatible throughout 1.x; additions are optional or defaulted. |
| SQLite | `PRAGMA user_version=1` | Forward migration only; newer schemas are rejected by older Agents. |
| Artifact manifest | `version: 2` | Immutable once written; consumers reject unsupported major manifest versions. |
| Python package | SemVer | Patch fixes defects, minor adds compatible capability, major may break a stable surface. |

`GET /version` is the machine-readable source for the running Agent version, supported API
identifiers, database schema, Artifact manifest versions, and transport mode. Every handled HTTP
response also carries `Trex-Agent-Version`. Clients should use versioned documents and feature
discovery rather than parsing the package version to infer individual fields.

The 1.0 reader accepts pre-release Catalog resources identified by `trex.example.io/v2alpha1` and
stored Plans identified by `trex.example.io/plan/v2alpha1`. It never rewrites an immutable legacy
Plan merely because it was read. Newly published resources and newly returned Plans always use the
stable identifiers. Legacy read support remains available throughout 1.x; clients must not create
new alpha documents.

Unknown request fields remain errors because the control plane is safety-sensitive. Compatible
evolution therefore adds optional fields with safe defaults, new endpoints, new enum values only
where clients are required to handle unknown values, or a new explicit API identifier. Removing a
field, changing units/default safety behavior, weakening validation, or changing verdict meaning
requires a new major/versioned surface.

Problem `code` is the automation contract; `detail` is diagnostic prose and may improve in patch
releases. A code does not change retryability or HTTP status within a stable major version.

## Client and server support

The supported combination is a CLI and Agent from the same major release. A newer 1.x CLI may use
an older 1.x Agent only after checking `/version`; it must fail clearly when an endpoint or document
identifier is unavailable. Cross-major operation is unsupported unless a release note names the
exact combination.

Database downgrade is never performed in place. Before an upgrade, preserve the automatic migration
backup and the installed wheel. If a newer release changes `PRAGMA user_version`, rollback means
stopping the Agent and restoring the pre-upgrade backup before starting the older wheel.

## Deprecation and release gate

A stable 1.x field or endpoint is deprecated for at least one minor release before removal in the
next major release. Deprecations appear in the changelog, documentation, and response metadata when
practical. A release candidate must pass resource/schema validation, Ruff, strict mypy, all tests,
wheel build, and clean-wheel smoke installation. It must also document database migration impact,
known hardware limitations, and any preview schema changes.
