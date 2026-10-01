# OpenID Connect Conformance

WeftID's OpenID Provider is tested with the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite), the open-source test suite the OpenID Foundation uses for its own certification program. WeftID runs the suite itself, in CI, and publishes the results on this page.

WeftID **passes the OpenID Foundation conformance suite** for the Basic OP, Config OP, Form Post OP, RP-Initiated OP, Front-Channel OP, Back-Channel OP, and 3rd Party-Init OP profiles, and for the Dynamic OP profile apart from one accepted deviation (see [Deviations](#deviations)). The same tests also run with clients that authenticate with `private_key_jwt`. It is **not** "OpenID Certified": that is the OpenID Foundation's certification mark, which requires a formal submission WeftID has chosen not to make. The evidence here is the suite's own output, and anyone can rerun it (see [Rerunning the suite](#rerunning-the-suite)).

## Results

<!-- conformance-results:start -->

* **Suite version:** 5.2.4
* **WeftID version:** 1.12.0 (`d6af3026`)
* **Run date:** 2026-10-01

| Profile | Test plan | Outcome | Passed | Warning | Review | Skipped | Failed |
|---|---|---|---|---|---|---|---|
| Basic OP | `oidcc-basic-certification-test-plan` | Green | 24 | 3 | 3 | 5 | 0 |
| Config OP | `oidcc-config-certification-test-plan` | Green | 1 | 0 | 0 | 0 | 0 |
| Form Post OP | `oidcc-formpost-basic-certification-test-plan` | Green | 24 | 3 | 3 | 5 | 0 |
| RP-Initiated OP | `oidcc-rp-initiated-logout-certification-test-plan` | Green | 3 | 0 | 8 | 0 | 0 |
| Front-Channel OP | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` | Green | 2 | 0 | 0 | 0 | 0 |
| Back-Channel OP | `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | Green | 2 | 0 | 0 | 0 | 0 |
| private_key_jwt clients | `oidcc-test-plan` | Green | 25 | 3 | 4 | 5 | 0 |
| Dynamic OP | `oidcc-dynamic-certification-test-plan` | Green (1 accepted failure) | 11 | 0 | 6 | 5 | 1 |
| 3rd Party-Init OP | `oidcc-3rdparty-init-login-certification-test-plan` | Green | 2 | 0 | 0 | 0 | 0 |

**Accepted failures** (each is a deviation listed below):

* `oidcc-discovery-endpoint-verification` (Dynamic OP): A Dynamic OP must support the implicit grant and the id_token and id_token token response types (OIDC Core 15.2). WeftID issues code only.

**Accepted warnings** (each is a deviation listed below):

* `oidcc-scope-profile` (Basic OP, Form Post OP, private_key_jwt clients): WeftID has no attributes for nickname, picture, website, gender, birthdate, middle_name, preferred_username, or profile; absent claims are omitted, never null (OIDC Core 5.1)
* `oidcc-ensure-request-with-acr-values-succeeds` (Basic OP, Form Post OP, private_key_jwt clients): WeftID defines no authentication context classes and emits no acr claim; the suite warns when acr_values was requested (SHOULD)
* `oidcc-claims-essential` (Basic OP, Form Post OP, private_key_jwt clients): The claims request parameter is not supported (claims_parameter_supported=false); claims are released by scope only, so name is absent without the profile scope (SHOULD)

**Expected skips:**

* `oidcc-scope-address` (Basic OP, Form Post OP, private_key_jwt clients): Address and phone scopes are not advertised; WeftID has no attributes to populate their claims
* `oidcc-scope-phone` (Basic OP, Form Post OP, private_key_jwt clients): Address and phone scopes are not advertised; WeftID has no attributes to populate their claims
* `oidcc-scope-all` (Basic OP, Form Post OP, private_key_jwt clients): Address and phone scopes are not advertised; WeftID has no attributes to populate their claims
* `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` (Basic OP, Form Post OP, private_key_jwt clients): Only signed request objects are accepted; request_object_signing_alg_values_supported does not list none, so the suite skips the unsigned-request-object module.
* `oidcc-ensure-request-object-with-redirect-uri` (Basic OP, Form Post OP, private_key_jwt clients, Dynamic OP): The module sends an unsigned request object; request_object_signing_alg_values_supported does not list none (only signed request objects are accepted), so the suite skips it.
* `oidcc-idtoken-unsigned` (Dynamic OP): ID tokens are always signed; id_token_signing_alg_values_supported does not list none, so the suite skips the unsigned ID token module.
* `oidcc-registration-sector-uri` (Dynamic OP): Pairwise subject identifiers are not supported yet (subject_types_supported lists only public), so the suite skips the sector_identifier_uri modules. The entry goes when pairwise subjects are supported.
* `oidcc-registration-sector-bad` (Dynamic OP): Pairwise subject identifiers are not supported yet (subject_types_supported lists only public), so the suite skips the sector_identifier_uri modules. The entry goes when pairwise subjects are supported.
* `oidcc-request-uri-unsigned` (Dynamic OP): Only signed request objects are accepted; request_object_signing_alg_values_supported does not list none, so the suite skips the unsigned request_uri module.

**Review** means the suite captured a screenshot (an error page, a second login page, or the consent page) for a person to judge, because it cannot judge page content itself:

* `oidcc-prompt-login` (Basic OP, Form Post OP, private_key_jwt clients)
* `oidcc-max-age-1` (Basic OP, Form Post OP, private_key_jwt clients)
* `oidcc-ensure-registered-redirect-uri` (Basic OP, Form Post OP, private_key_jwt clients)
* `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-modified-id-token-hint` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-no-id-token-hint` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-no-params` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-no-post-logout-redirect-uri` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-only-state` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-bad-id-token-hint` (RP-Initiated OP)
* `oidcc-redirect-uri-query-added` (private_key_jwt clients, Dynamic OP)
* `oidcc-ensure-redirect-uri-in-authorization-request` (Dynamic OP)
* `oidcc-redirect-uri-query-mismatch` (Dynamic OP)
* `oidcc-registration-logo-uri` (Dynamic OP)
* `oidcc-registration-policy-uri` (Dynamic OP)
* `oidcc-registration-tos-uri` (Dynamic OP)

<!-- conformance-results:end -->

### Reading the table

Each profile is one test plan made of test modules. A profile is **green** when every module finishes as one of:

* **Passed**: every check succeeded.
* **Warning**: the provider did something the specification allows but recommends against (a SHOULD). Every warning WeftID accepts is listed by name under the table and explained in [Deviations](#deviations).
* **Review**: the module passed its automated checks and captured a screenshot for a person to judge, because the suite cannot judge page content. These are the error page for an unregistered redirect URI, the second login page for `prompt=login` and `max_age`, the sign-out confirmation and signed-out pages for RP-initiated logout, and the consent page showing a registered client's logo, privacy policy, and terms of service links.
* **Skipped**: the module tests a feature WeftID does not offer and says so in its discovery document (for example the `address` and `phone` scopes, or unsigned request objects).

A single **Failed** or unfinished module makes the profile red, unless it is an **accepted failure**: a check WeftID fails on purpose, listed by name under the table and explained in [Deviations](#deviations). Dynamic OP has one.

The **private_key_jwt clients** row is not a certification profile. The certification plans fix how the test clients authenticate (client secrets), so WeftID also runs the suite's general OpenID Connect test plan with static clients that authenticate with `private_key_jwt`.

The runner compares every run against two files checked into the repository: [`expected-failures.json`](https://github.com/Pageloom/weft-id/blob/main/dev/oidc-conformance/expected-failures.json) (the accepted warnings and failures) and [`expected-skips.json`](https://github.com/Pageloom/weft-id/blob/main/dev/oidc-conformance/expected-skips.json). A run fails on anything these files do not list, and also on an entry that no longer happens, so the files cannot quietly go stale.

## Profiles not tested

* **Implicit OP** and **Hybrid OP**: WeftID issues authorization codes only (`response_type=code`). The implicit and hybrid flows return tokens through the browser, and current OAuth security guidance advises against them.
* **Session OP** (OpenID Connect Session Management): the `check_session_iframe` mechanism relies on third-party cookies, which browsers now block.

## Deviations

These are the places where WeftID knowingly differs from what the suite checks for or recommends:

* **No `acr` claim.** WeftID defines no authentication context classes, so it returns no `acr` claim when a relying party sends `acr_values`. The suite warns (SHOULD).
* **No `claims` request parameter.** Claims are released by scope only, and discovery says `claims_parameter_supported: false`. The suite warns when a claim requested through `claims` is absent (SHOULD).
* **Partial `profile` claim set.** The `profile` scope releases the claims WeftID holds data for: `name`, `given_name`, `family_name`, `locale`, `zoneinfo`, and `updated_at`. Claims without data (`nickname`, `picture`, `website`, `gender`, `birthdate`, `middle_name`, `preferred_username`, `profile`) are omitted, never sent as `null`, as OpenID Connect Core section 5.1 allows. The suite warns.
* **Signed request objects only.** Request objects must be signed (`RS256`, `PS256`, or `ES256`). Discovery does not list `none` in `request_object_signing_alg_values_supported`, so the suite skips its unsigned request object modules (by value and by reference).
* **Dynamic OP discovery check.** A Dynamic OP must list the implicit grant and the `id_token` and `id_token token` response types in its discovery document (OpenID Connect Core section 15.2). WeftID issues authorization codes only, so `oidcc-discovery-endpoint-verification` fails in the Dynamic OP plan. Every other Dynamic OP module passes or is skipped.
* **No pairwise subject identifiers yet.** Every client gets the same `sub` for a user (`subject_types_supported` lists `public` only), so the suite skips its `sector_identifier_uri` registration modules.
* **Unsigned ID tokens are never issued.** Discovery does not list `none` in `id_token_signing_alg_values_supported`, so the suite skips its unsigned ID token module.
* **No mutual-TLS client authentication.** Confidential clients authenticate with a client secret or `private_key_jwt`; mTLS client authentication (RFC 8705) is not supported.
* **No `address` or `phone` scopes.** WeftID has no attributes to fill them, so they are not advertised and the suite skips their modules.
* **Re-authentication is local.** `prompt=login` and an expired `max_age` make the user sign in to WeftID again (password, then two-step verification per policy). The re-authentication is not passed on to an upstream SAML or OIDC identity provider.

One known limitation is not a conformance deviation, but is listed so this page does not overstate things: expired OAuth2 access and refresh tokens stop working at expiry but are not yet deleted from the database.

## How results are kept current

The suite runs in a GitHub Actions workflow ([`oidc-conformance.yml`](https://github.com/Pageloom/weft-id/blob/main/.github/workflows/oidc-conformance.yml)) on the same schedule as WeftID's end-to-end tests: nightly when there were commits, on request for a pull request, and on manual dispatch. Each run uploads the suite's full signed logs as a workflow artifact and writes this table to the run summary.

The suite version is pinned. Upgrading it is a deliberate change, because a new release can add tests. The table above is refreshed for every WeftID release from a green run on the release commit.

## Rerunning the suite

Everything needed is in the WeftID repository. With Docker and Poetry installed:

```bash
make up                        # WeftID dev stack
make oidc-conformance-up       # the conformance suite, pinned release
make oidc-conformance          # provision a test tenant and clients, run the plans
make oidc-conformance-report   # print this page's results table from the run
```

The suite UI at `https://localhost.emobix.co.uk:8443/` shows every module's log, including the scripted browser's page snapshots. The [walkthrough](https://github.com/Pageloom/weft-id/blob/main/dev/oidc-conformance.md) covers prerequisites, how the browser automation works, and running a subset of modules.
