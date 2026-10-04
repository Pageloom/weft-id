# Versioning Policy

WeftID follows [Semantic Versioning](https://semver.org/) (SemVer). The canonical version
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

## Release Checklist

1. On `main`, move the `Unreleased` entries in `CHANGELOG.md` under the new version and bump
   the version in `pyproject.toml`. Commit.
2. Refresh the [OpenID Connect conformance results](conformance/oidc.md) from that commit:
   `make oidc-conformance`, then `make oidc-conformance-report ARGS="--write-docs"`. Commit
   the updated page. A red profile blocks the release.
3. Push `main`. Wait for the `sync-prod-requirements` workflow, then pull any commit it made.
4. Run `make release-tag`. It creates the tag (`v1.2.3`) on the resulting `HEAD` from the
   version in `pyproject.toml`, so the name is never typed by hand. It refuses unless you are
   on a clean `main` that equals `origin/main` and `CHANGELOG.md` has a section for the
   version.
5. Push the tag with the command it prints. The publish workflow checks that the tag matches
   `pyproject.toml`, that the image can be pulled anonymously, and runs the self-hosting smoke
   test (fresh install on amd64 and arm64, plus an upgrade from the previous release). The
   GitHub Release is only created when all of them pass. Run `make selfhost-smoke` beforehand
   to catch problems before tagging.
