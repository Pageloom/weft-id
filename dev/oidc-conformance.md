# OIDC conformance suite (OpenID Foundation)

Run the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against WeftID's OpenID Provider, locally, in Docker. The suite is the
quality bar for the OIDC provider: the certification test plans for the
profiles WeftID supports must be green before a release, and the results
are published so anyone can rerun them.

WeftID does not pursue formal OIDF certification. The wording rule for docs
and marketing is therefore "passes the OpenID Foundation conformance suite
for profiles X, Y, Z", never "OpenID Certified" (that is OIDF's mark).

The suite runs entirely **outside** the WeftID repo by default. Its compose
file, Mongo data directory, downloaded runner scripts, and the rendered plan
config (which holds client secrets) live under
`~/.local/share/weft-id/oidc-conformance/`. Override with the
`OIDC_CONFORMANCE_DIR` env var or `--dir <path>`. The only things that land
in this checkout are the exported result zips under
`dev/oidc-conformance/export/`, which is gitignored.

## Prerequisites

* The WeftID dev stack running: `make up`. The proxy must have been
  (re)created since `dev/docker-compose.yml` gained the
  `oidc-conformance.weftid.localhost` network alias; `make up` does this.
* `BYPASS_OTP=true` in `.env` (the dev default). The suite's scripted
  browser passes the MFA step with any six-digit code.
* Poetry environment installed (`poetry install`). The suite's runner is a
  Python script that needs `httpx` and `pyparsing`, both already present.

## Quick start

```bash
make oidc-conformance-up     # first run pulls the pinned suite images
make oidc-conformance        # provision tenant + clients, run the plans
```

The first `up` writes the compose file, discovers WeftID's `devnet` network
name from the running `dev_app` container, and starts three containers
(`weft_oidc_conformance_server`, `_nginx`, `_mongo`). The suite UI is at
`https://localhost.emobix.co.uk:8443/` (a public DNS name that resolves to
127.0.0.1; the nginx in front uses a self-signed certificate, accept the
warning).

`make oidc-conformance` then:

1. downloads the suite's `run-test-plan.py` for the pinned release into the
   runtime dir (once per release),
2. runs `app/dev/oidc_conformance_testbed.py` inside the app container to
   provision the `oidc-conformance` tenant, a member user, and three
   OIDC-enabled clients registered with the suite's callback URL and its
   `post_logout_redirect` URL, plus a fourth that also has the suite's
   `frontchannel_logout` URL (used only by the front-channel module, through
   a config override: any other module that ends a session would otherwise
   load a logout iframe it does not expect), and a fifth with the suite's
   `backchannel_logout` URL (used only by the back-channel module, for the
   same reason). A sixth and seventh client authenticate with
   `private_key_jwt`, each registered with the public half of a fresh RSA
   key; the private JWKS goes into the plan config. It also turns on
   dynamic client registration for the tenant (open, new clients available
   to all users: the suite sends the initial access token with a module's
   first registration only), mints a fresh initial access token, and deletes
   the clients and tokens earlier runs left behind,
3. renders `dev/oidc-conformance/config.template.json` (static-client
   plans), `config-private-key-jwt.template.json` (the `private_key_jwt`
   clients) and `config-dynamic.template.json` (plans that register their
   own clients, with the initial access token) into the runtime directory.
   The last two inherit the static config's browser automation (see below),
4. runs the Basic OP, Config OP, Form Post OP, RP-Initiated OP,
   Front-Channel OP, Back-Channel OP, Dynamic OP, and 3rd Party-Init OP
   certification plans, plus the general `oidcc-test-plan` with the
   `private_key_jwt` clients (the certification plans fix client
   authentication to client secrets), one module at a time, and exports
   the results.

The run exits non-zero unless every module finished and the outcome
matches `dev/oidc-conformance/expected-failures.json` and
`expected-skips.json` exactly.

When you're done for the day:

```bash
make oidc-conformance-down      # stop containers, keep Mongo data
make oidc-conformance-destroy   # stop + wipe Mongo data + remove the dir
```

## Reading results

* **Terminal.** The runner prints one line per test module with PASSED,
  WARNING, REVIEW, SKIPPED, FAILED, or INTERRUPTED, then a per-plan summary.
  With `ARGS="--verbose"` it also prints, for every unexpected failure, a
  ready-to-paste JSON template for the expected-failures file.
* **Suite UI.** Each plan line carries a `plan-detail.html?plan=...` link.
  Open it to browse every module's log, including the scripted browser's
  page snapshots.
* **Export.** `dev/oidc-conformance/export/` holds one zip per plan per run
  with the full signed logs. CI uploads this directory as the run artifact.
* **Report.** `make oidc-conformance-report` prints the results table (suite
  and WeftID versions, run date, per-profile counts, and the accepted
  warnings, expected skips, and review modules by name) from the newest run
  of each plan in the export directory. `ARGS="--write-docs"` writes it into
  the marked section of `docs/conformance/oidc.md`; the release checklist in
  `docs/VERSIONING.md` does this for every release.

A profile is green when every module is PASSED, WARNING, REVIEW, or
SKIPPED and none is FAILED or INTERRUPTED, apart from accepted failures:
FAILED modules whose failing conditions all have an expected-failures entry
with `"expected-result": "failure"`. There is one, the Dynamic OP plan's
`oidcc-discovery-endpoint-verification` (it requires implicit and hybrid
response types, which WeftID does not offer). The report lists accepted
failures by name.

## The expected-failures file

`dev/oidc-conformance/expected-failures.json` lists the conditions that are
known to fail, one entry per failing condition with a one-line `comment`.
The runner fails on an unexpected failure **and** on an expected failure
that did not happen, so the file cannot go stale: fixing a gap means
removing its entry. The file holds no failures, only the warnings WeftID
accepts as deviations; each is explained on the public results page
(`docs/conformance/oidc.md`). Comments in both expected files are published
there verbatim, so write them for relying-party developers.

Entries have the suite's shape; `--verbose` prints them ready to paste:

```json
{
    "test-name": "oidcc-prompt-login",
    "variant": "*",
    "configuration-filename": "*config.json",
    "current-block": "Second authorization: check auth_time",
    "condition": "CheckSecondIdTokenAuthTimeIsLaterIfPresent",
    "expected-result": "failure",
    "comment": "prompt=login not honoured yet (Iteration 2)"
}
```

`dev/oidc-conformance/expected-skips.json` works the same way for modules
the suite skips (for example a scope WeftID does not advertise).

## How the browser automation works

The plan config's `browser` section scripts the interactive steps in the
suite's built-in headless browser (HtmlUnit): the login email step, the
password step, the MFA code, and the consent page. Every step is optional
because an existing session or remembered consent skips it. The final step
waits for the suite's own callback page. Per-module `override` entries
handle tests that expect an error page instead of a redirect (for example
an unregistered `redirect_uri`) or a second login page (`prompt=login`).

A second top-level entry drives the end session endpoint for the
RP-Initiated OP plan: it clicks **Sign out** on the confirmation page when
one is shown, snapshots the signed-out page, and accepts the redirect back
to the suite. The modules that must see the confirmation page (bad or
missing `id_token_hint`, unregistered `post_logout_redirect_uri`) override
it to snapshot that page instead. In the Front-Channel OP plan the end
session request lands on the "Signing you out" page, whose iframe calls the
suite's `frontchannel_logout` endpoint and whose meta refresh continues to
the suite's `post_logout_redirect`; none of the logout tasks acts on it.
In the Back-Channel OP plan the browser goes straight back to the suite;
the logout token arrives separately from WeftID's worker (within about ten
seconds, its polling interval), which reaches the suite over the dev network.
The suite's certificate is self-signed and its address is private, so the
worker's HTTP client allows that one host and skips TLS verification for it,
in dev only (`IS_DEV`).

The suite replaces the whole `browser` list for an overridden module, so an
override that still needs the login script names it as `"$browser[0]"`. The
runner expands such references to a copy of the top-level entry when it
renders the config; a reference to an entry that does not exist is an
error.

The `private_key_jwt` and dynamic templates only describe their clients.
The runner gives them the static config's `options` and `browser` sections
and every override that only scripts the browser (error pages, forced
re-login), since those pages do not depend on the client. Overrides that
swap the client (front- and back-channel logout) stay with the static
config. A template's own keys and overrides win, and its overrides may use
`"$browser[N]"` references to the inherited entries.

The Dynamic OP plan's `oidcc-registration-logo-uri`, `-policy-uri` and
`-tos-uri` modules want a screenshot of a page showing the registered logo
or link. WeftID's consent page shows them, so their overrides log in,
snapshot the consent page and stop. The filled placeholder ends the module;
consenting as well makes the callback race the end of the module, and the
suite then interrupts it with an internal error.

## Operator steps

`oidcc-server-rotate-keys` (in the Dynamic OP plan and the general test
plan) pauses until the operator has rotated the OP's signing keys. The suite's
runner cannot do that, so `make oidc-conformance` runs it through
`dev/oidc_conformance_hooks.py`, which patches the runner's client in-process:
before starting that module, it rotates the conformance tenant's key with
`oidc_conformance_testbed.py --rotate-signing-key-flag` in the app container.
The testbed ends any running rotation grace period first (real tenants must
wait it out), so back-to-back runs work.

Rotation is why the run is serial (`--no-parallel`): the runner would
otherwise run each alias's plans side by side, and a rotation in the Dynamic
OP plan would swap the key under a Basic OP module that already fetched the
JWKS.

The browser reaches WeftID through the dev reverse proxy: the suite joins
WeftID's `devnet` network and the proxy carries a network alias for the
conformance tenant host. WeftID's containers reach the suite the same way
via the `localhost.emobix.co.uk` alias on the suite's nginx. TLS needs no
extra trust setup: the suite deliberately does not validate the certificate
of the server under test.

## Rate limits during a run

Every module logs the conformance user in from a fresh browser, and modules
that fail early take about a second each. WeftID's login limits (five MFA
attempts per user per fifteen minutes, per-IP limits on the email step) are
tuned for people, not for forty logins in ten minutes, so the runner flushes
memcached once a second for the duration of the run, the same reset the E2E
fixtures perform before each testbed. This only touches rate-limit counters:
the OTP passes via `BYPASS_OTP`, sessions are cookies, and codes and tokens
live in Postgres. Do not run `make e2e` at the same time; its rate-limit
tests would see the resets.

## CI

`.github/workflows/oidc-conformance.yml` runs the same plans on the
E2E workflow's triggers: nightly when there were commits, the `run-e2e` pull
request label, and manual dispatch. It brings up the dev stack exactly as the
E2E job does, then calls `dev/oidc-conformance.sh up` and
`dev/oidc_conformance.py run`, the same scripts as a local run, with the suite
runtime directory next to the checkout. The runner needs only `httpx` and
`pyparsing` (pinned to the `poetry.lock` versions), so the job skips the
Poetry install. The job fails on any mismatch with the expected files; the
report goes to the run summary and the export directory (plus `report.md`) is
uploaded as the `oidc-conformance-results` artifact either way.

The E2E workflow removes the `run-e2e` label; this workflow only reads it.

## Running a subset

The runner passes unknown arguments through to `run-test-plan.py`:

```bash
make oidc-conformance ARGS="--list"          # numbered plan list, no run
make oidc-conformance ARGS="--rerun 1:5"     # plan 1, module 5 only
```

The runner always passes `--no-parallel` (see [Operator steps](#operator-steps)).

Or call the runner directly, for example with a different runtime dir:

```bash
poetry run python dev/oidc_conformance.py run --runtime-dir /tmp/suite --verbose
./dev/oidc-conformance.sh up --dir /tmp/suite --tag release-v5.2.4
```

## Lifecycle commands

| Command                            | Action                                        |
|------------------------------------|-----------------------------------------------|
| `make oidc-conformance-up`         | Create dir + compose if missing, start        |
| `make oidc-conformance`            | Provision testbed, run the plans              |
| `make oidc-conformance-report`     | Results table from the newest run             |
| `make oidc-conformance-down`       | Stop containers, keep Mongo data              |
| `make oidc-conformance-destroy`    | Stop, wipe data, remove the runtime dir       |
| `make oidc-conformance-status`     | `docker compose ps` for the suite             |
| `make oidc-conformance-logs`       | Follow combined logs                          |
| `make oidc-conformance-info`       | Reprint URLs and the walkthrough              |

## Pinned release

The suite version is pinned in two places that must agree:
`DEFAULT_TAG` in `dev/oidc-conformance.sh` (images) and
`DEFAULT_SUITE_TAG` in `dev/oidc_conformance.py` (runner scripts). Bump both
deliberately; a new release can add tests, and the published results record
the version they were produced with.

## Credits and licensing

The conformance suite is developed by the OpenID Foundation and released
under the Apache License 2.0. WeftID does not bundle, vendor, or
redistribute any of its code or images: the script pulls the public images
at runtime and the runner downloads `run-test-plan.py` from the pinned
release tag. The compose template written by `dev/oidc-conformance.sh` is
adapted from the suite's own `docker-compose-prebuilt.yml` and credits it in
the file header.
