# Security Policy

WeftID is identity infrastructure, so we take vulnerability reports seriously and
appreciate the work that goes into them.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security problem.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/Pageloom/weft-id/security/advisories/new)

The report is visible only to you and the maintainers. Please include:

- The affected version or commit, and how WeftID is deployed (self-hosted image, dev stack)
- What an attacker can do, and what they need to do it (anonymous, signed-in user, admin, a registered client)
- Steps to reproduce, or a proof of concept
- Any fix or mitigation you have in mind

## What to expect

- An acknowledgement within 5 business days
- An assessment (accepted, needs more information, or not a vulnerability) within 14 days
- For accepted reports: a fix in a patch release, and a published advisory that credits you
  unless you ask us not to

Please give us a reasonable chance to release a fix before you disclose the issue publicly.
We will tell you when the fix ships.

## Supported versions

Security fixes are released for the latest minor version only. If you run an older version,
upgrade to the latest release to receive them. See [docs/VERSIONING.md](docs/VERSIONING.md).

## Scope

In scope: the code in this repository and the published `ghcr.io/pageloom/weft-id` images,
including authentication and session handling, SAML and OIDC flows, tenant isolation,
SCIM, the API, and the self-hosting files under `deploy/`.

Out of scope:

- Vulnerabilities in third-party dependencies with no demonstrated impact on WeftID
  (report those upstream; Dependabot tracks the rest)
- Findings that require a compromised host, database, or `SECRET_KEY`
- Missing hardening with no practical attack (for example a header on a static asset)
- Denial of service by sheer request volume
- Social engineering, and anything against deployments you do not own or have permission to test

There is no bug bounty.
