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
