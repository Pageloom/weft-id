# SCIM testbed (Authentik)

Bootstrap an [Authentik](https://goauthentik.io) instance for testing
WeftID's outbound SCIM 2.0 provider against a real, free SCIM
receiver. Authentik mints a bearer token and exposes a SCIM 2.0 base
URL that WeftID pushes into.

This script runs Authentik entirely **outside** the WeftID repo by
default. The compose file, generated secrets, postgres volume, and
mounted directories all live under
`~/.local/share/weft-id/scim-testbed/authentik/`. Override with the
`SCIM_TESTBED_DIR` env var or `--dir <path>`. Nothing the script
writes lands in this checkout.

> **Need an interop check, not a real receiver?** See
> [Closed-loop SCIM self-test](#closed-loop-scim-self-test) below. It
> points WeftID's outbound SCIM at WeftID's *own* inbound endpoint, so it
> runs entirely inside the Docker E2E stack with no external dependency.
> Use the Authentik testbed for true third-party interop; use the loopback
> for fast self-consistency and regression guarding in CI.

## Quick start

```bash
make scim-testbed-up
```

The first run downloads the Authentik images, generates the secrets,
starts the containers, and prints the wire-up walkthrough. Subsequent
runs are fast (containers come back up against the existing volume).

When you're done for the day:

```bash
make scim-testbed-down     # stop containers, keep the DB volume
make scim-testbed-destroy  # stop + wipe DB volume + remove the dir
```

## Wire it up in WeftID

After `make scim-testbed-up` returns, follow the printed steps:

1. Open `http://localhost:9000/if/flow/initial-setup/` and set a
   password for the `akadmin` user.
2. In Authentik's Admin UI: **Directory → Federation → Sources**.
   Create a **SCIM Source**:
   - Name: `WeftID`
   - Slug: `weftid`
3. Open the new source. Copy the bearer token (eye icon) and note the
   SCIM Base URL.
4. In WeftID's SCIM tab on any SP:
   - Application type: **Generic SCIM 2.0**
   - Target URL:
     `http://host.docker.internal:9000/source/scim/weftid/v2/`
     (the `host.docker.internal` form is allowed in `IS_DEV` mode so
     WeftID's app/worker containers can reach Authentik on the host)
   - Click **Import existing token** and paste Authentik's token.
5. Grant a group access on the SP. The membership change enqueues
   SCIM pushes that should land in Authentik's **Directory → Users**
   within seconds.

## What this exercises

Outbound SCIM end-to-end:

- POST `/Users` and POST `/Groups` (first-push capture of the
  receiver's `id` into `sp_scim_remote_ids`)
- PUT `/Users/<remote_id>` and PUT `/Groups/<remote_id>` (subsequent
  updates using the captured id)
- DELETE `/Users/<remote_id>` (deprovisioning when a grant is removed)
- 404-on-DELETE → `absent` PushStatus (deprovisioning a user the
  receiver never saw — surfaces as the amber **Skipped** badge in the
  Sync activity panel)
- The **Import existing token** mode of WeftID's SCIM credentials
  (Authentik does not accept a bearer minted elsewhere)

## Lifecycle commands

| Command                          | Action                                       |
|----------------------------------|----------------------------------------------|
| `make scim-testbed-up`           | Create dir + secrets if missing, start       |
| `make scim-testbed-down`         | Stop containers, keep DB volume              |
| `make scim-testbed-destroy`      | Stop, drop volume, remove the testbed dir    |
| `make scim-testbed-status`       | `docker compose ps` for the testbed          |
| `make scim-testbed-logs`         | Follow combined logs                         |
| `make scim-testbed-info`         | Reprint the wire-up walkthrough              |

For finer control, call the script directly:

```bash
./dev/scim-testbed.sh up --dir /tmp/my-authentik --port 9100
./dev/scim-testbed.sh logs server
./dev/scim-testbed.sh help
```

Or set env vars: `SCIM_TESTBED_DIR`, `SCIM_TESTBED_PORT_HTTP`,
`SCIM_TESTBED_PORT_HTTPS`, `SCIM_TESTBED_TAG`.

## Closed-loop SCIM self-test

For a self-contained check that needs **no external receiver**, WeftID
points its *outbound* SCIM at its *own* inbound SCIM endpoint for a
separate receiving tenant. The whole loop closes inside the Docker E2E
stack: the worker reaches the app container at `http://app:8000/...` over
the `devnet` bridge and POSTs/PUTs/DELETEs Generic SCIM 2.0 payloads that
must parse cleanly in our own inbound parser.

**What it exercises** (full lifecycle, against one provisioned test bed):

* provision: source members POST `/Users`, the granted group POST `/Groups`
* update: an attribute change PUTs `/Users/<remote_id>`, reusing the
  captured remote id (no duplicate POST)
* membership round-trip: the receiver `idp` group's members match the
  source group's, compared by remote id
* deprovision: removing the grant DELETEs `/Users/<remote_id>`; the
  receiver soft-deletes the user (`is_inactivated=true`) and keeps MFA
  and history
* across the whole lifecycle, **zero** dead-letters

**Why.** It is a self-consistency check (the payloads we emit must satisfy
our own inbound parser) and a regression guard against either half drifting
from the contract. It earned its keep on the first run: it surfaced
migration `0045`'s bug, where every authenticated inbound SCIM request
returned 401 in dev and production because the `scim_inbound_tokens` RLS
policy had no UNSCOPED escape hatch for the pre-tenant token lookup.

**How to run.** Bring the dev stack up (`make up`) and run the loopback
E2E test:

```bash
make e2e ARGS="-k scim_loopback"
```

The test provisions both tenants via the headless
`app/dev/scim_loopback_testbed.py` script (run inside the app container)
and triggers worker drains on demand. The same script's `--mutate-user`
and `--remove-grant` flags drive the update and deprovision steps through
the service layer (so the event log fires the right SCIM trigger); pass
`--json-output` to get a machine-readable result on stdout.

## Why this isn't committed as a fixture

Authentik isn't part of WeftID's source. Treating it as a
disposable, self-contained external runtime keeps the repo
uncluttered, prevents accidental commits of generated secrets, and
makes it obvious that the testbed is local-only. Anyone can wipe and
recreate the testbed without affecting the project.

If you do bootstrap a testbed inside the checkout (e.g. with
`./dev/scim-testbed.sh up --dir dev/authentik`), `.gitignore` covers
both `dev/authentik/` and `dev/scim-testbed/` so it stays out of
source.

## Credits and licensing

[Authentik](https://goauthentik.io) is a separate open-source identity
provider maintained by Authentik Security Inc. The Authentik server is
MIT-licensed; its documentation (including the compose example this
script is adapted from) is CC BY-SA 4.0. The script and walkthrough in
this directory are MIT-licensed along with the rest of WeftID. WeftID
does not bundle, vendor, or redistribute any Authentik code or images.
The compose template the script writes is adapted from Authentik's
official docs and credits them in the file header.
