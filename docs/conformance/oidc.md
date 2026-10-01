# OpenID Connect Conformance

WeftID's OpenID Provider is tested with the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite), the open-source test suite the OpenID Foundation uses for its own certification program. WeftID runs the suite itself, in CI, and publishes the results on this page.

WeftID **passes the OpenID Foundation conformance suite** for the Basic OP, Config OP, Form Post OP, RP-Initiated OP, Front-Channel OP, Back-Channel OP, and 3rd Party-Init OP profiles. It is **not** "OpenID Certified": that is the OpenID Foundation's certification mark, which requires a formal submission WeftID has chosen not to make. The evidence here is the suite's own output, and anyone can rerun it (see [Rerunning the suite](#rerunning-the-suite)).

## Results

<!-- conformance-results:start -->

* **Suite version:** 5.2.4
* **WeftID version:** 1.12.0 (`9e6fa703`)
* **Run date:** 2026-10-01

| Profile | Test plan | Outcome | Passed | Warning | Review | Skipped | Failed |
|---|---|---|---|---|---|---|---|
| Basic OP | `oidcc-basic-certification-test-plan` | Green | 24 | 3 | 4 | 4 | 0 |
| Config OP | `oidcc-config-certification-test-plan` | Green | 1 | 0 | 0 | 0 | 0 |
| Form Post OP | `oidcc-formpost-basic-certification-test-plan` | Green | 24 | 3 | 4 | 4 | 0 |
| RP-Initiated OP | `oidcc-rp-initiated-logout-certification-test-plan` | Green | 3 | 0 | 8 | 0 | 0 |
| Front-Channel OP | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` | Green | 2 | 0 | 0 | 0 | 0 |
| Back-Channel OP | `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | Green | 2 | 0 | 0 | 0 | 0 |
| 3rd Party-Init OP | `oidcc-3rdparty-init-login-certification-test-plan` | Green | 2 | 0 | 0 | 0 | 0 |

**Accepted warnings** (each is a deviation listed below):

* `oidcc-scope-profile` (Basic OP, Form Post OP): WeftID has no attributes for nickname, picture, website, gender, birthdate, middle_name, preferred_username, or profile; absent claims are omitted, never null (OIDC Core 5.1)
* `oidcc-ensure-request-with-acr-values-succeeds` (Basic OP, Form Post OP): WeftID defines no authentication context classes and emits no acr claim; the suite warns when acr_values was requested (SHOULD)
* `oidcc-claims-essential` (Basic OP, Form Post OP): The claims request parameter is not supported (claims_parameter_supported=false); claims are released by scope only, so name is absent without the profile scope (SHOULD)

**Expected skips:**

* `oidcc-scope-address` (Basic OP, Form Post OP): Address and phone scopes are not advertised; WeftID has no attributes to populate their claims
* `oidcc-scope-phone` (Basic OP, Form Post OP): Address and phone scopes are not advertised; WeftID has no attributes to populate their claims
* `oidcc-scope-all` (Basic OP, Form Post OP): Address and phone scopes are not advertised; WeftID has no attributes to populate their claims
* `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` (Basic OP, Form Post OP): Request objects are rejected with request_not_supported and discovery says request_parameter_supported=false; the suite skips the remainder of the module (the 'rejected as unsupported' outcome).

**Review** means the suite captured a screenshot (an error page, or a second login page) for a person to judge, because it cannot judge page content itself:

* `oidcc-prompt-login` (Basic OP, Form Post OP)
* `oidcc-max-age-1` (Basic OP, Form Post OP)
* `oidcc-ensure-registered-redirect-uri` (Basic OP, Form Post OP)
* `oidcc-ensure-request-object-with-redirect-uri` (Basic OP, Form Post OP)
* `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-modified-id-token-hint` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-no-id-token-hint` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-no-params` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-no-post-logout-redirect-uri` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-only-state` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri` (RP-Initiated OP)
* `oidcc-rp-initiated-logout-bad-id-token-hint` (RP-Initiated OP)

<!-- conformance-results:end -->

### Reading the table

Each profile is one test plan made of test modules. A profile is **green** when every module finishes as one of:

* **Passed**: every check succeeded.
* **Warning**: the provider did something the specification allows but recommends against (a SHOULD). Every warning WeftID accepts is listed by name under the table and explained in [Deviations](#deviations).
* **Review**: the module passed its automated checks and captured a screenshot for a person to judge, because the suite cannot judge page content. These are the error page for an unregistered redirect URI, the second login page for `prompt=login` and `max_age`, and the sign-out confirmation and signed-out pages for RP-initiated logout.
* **Skipped**: the module tests a feature WeftID does not offer and says so in its discovery document (for example the `address` and `phone` scopes, or request objects).

A single **Failed** or unfinished module makes the profile red.

The runner compares every run against two files checked into the repository: [`expected-failures.json`](https://github.com/Pageloom/weft-id/blob/main/dev/oidc-conformance/expected-failures.json) (the accepted warnings) and [`expected-skips.json`](https://github.com/Pageloom/weft-id/blob/main/dev/oidc-conformance/expected-skips.json). A run fails on anything these files do not list, and also on an entry that no longer happens, so the files cannot quietly go stale.

## Profiles not tested

* **Implicit OP** and **Hybrid OP**: WeftID issues authorization codes only (`response_type=code`). The implicit and hybrid flows return tokens through the browser, and current OAuth security guidance advises against them.
* **Session OP** (OpenID Connect Session Management): the `check_session_iframe` mechanism relies on third-party cookies, which browsers now block.

Dynamic OP is planned. Dynamic client registration itself is implemented (the 3rd Party-Init OP plan registers its clients with it), but the Dynamic OP plan also requires `private_key_jwt` client authentication, request objects, and signed userinfo responses. It will be added to the table once those are implemented and it passes.

## Deviations

These are the places where WeftID knowingly differs from what the suite checks for or recommends:

* **No `acr` claim.** WeftID defines no authentication context classes, so it returns no `acr` claim when a relying party sends `acr_values`. The suite warns (SHOULD).
* **No `claims` request parameter.** Claims are released by scope only, and discovery says `claims_parameter_supported: false`. The suite warns when a claim requested through `claims` is absent (SHOULD).
* **Partial `profile` claim set.** The `profile` scope releases the claims WeftID holds data for: `name`, `given_name`, `family_name`, `locale`, `zoneinfo`, and `updated_at`. Claims without data (`nickname`, `picture`, `website`, `gender`, `birthdate`, `middle_name`, `preferred_username`, `profile`) are omitted, never sent as `null`, as OpenID Connect Core section 5.1 allows. The suite warns.
* **No request objects.** The `request` and `request_uri` parameters are rejected with `request_not_supported`, and discovery says so. The suite accepts this and skips the rest of the module.
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
