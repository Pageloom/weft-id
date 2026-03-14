# Versioning Policy

WeftId follows [Semantic Versioning](https://semver.org/) (SemVer). The canonical version
lives in `pyproject.toml` and is readable at runtime via `app.version.__version__`.

## Version Levels

**Patch** (1.0.x) — Bug fixes, security patches. No schema migrations, no API changes,
no SAML/OAuth behavior changes. Self-hosters can pull and restart with no other action.

**Minor** (1.x.0) — New features, additive API endpoints, non-breaking schema migrations
(new columns with defaults, new tables), new env vars with sensible defaults, UI
improvements. Self-hosters pull, restart, and auto-migration runs. Review the changelog
for new features.

**Major** (x.0.0) — Removed or changed API endpoints, required new env vars without
defaults, SAML assertion format or attribute mapping behavior changes, SSO flow changes
requiring SP/IdP reconfiguration, compose file structural changes (new required services,
renamed volumes). Read the migration guide. May require SP/IdP reconfiguration.

## Identity-Specific Rules

Identity platforms carry extra weight because a seemingly minor change can silently break
federation trust for every downstream SP.

* Any change to SAML assertion structure, entityID format, or default attribute mappings
  is a **major** bump.
* New optional SAML/OAuth features (e.g., a new optional attribute) are **minor**.
* Changes to the consent screen UI that don't alter what data is shared are **minor**.

## Git Tags

* Format: `v1.0.0` (prefixed with `v`).
* Tags are created on the `main` branch only, after all checks pass.
* The tag version must match the version in `pyproject.toml`.

## Docker Images

Docker images are labeled with OCI metadata including the version. The GHCR publish
workflow (triggered by version tags) produces multi-tag images:

* Exact version: `1.2.3`
* Minor: `1.2`
* Major: `1`
* `latest` (newest stable release)

Self-hosters can pin to their preferred level of update granularity.
