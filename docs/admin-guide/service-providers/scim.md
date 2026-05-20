# Outbound SCIM Provisioning

WeftID can push user and group changes to downstream applications using SCIM 2.0. When a user is added to a group, has their attributes updated, or loses access, WeftID notifies the downstream application so it can create, update, or deactivate the corresponding account without manual intervention.

This is a placeholder note. The full setup guide (with screenshots, troubleshooting, and per-vendor walkthroughs) lands in the next documentation pass.

## Supported vendors (day one)

WeftID ships with quirk modules for four downstream applications:

* **Slack** (Slack Enterprise Grid SCIM)
* **GitHub Enterprise Cloud** (Enterprise SCIM)
* **Atlassian** (Atlassian Guard / Access provisioning)
* **GitLab** (GitLab.com group SAML SCIM)

Any other SCIM 2.0 compliant application can be configured using the **Generic** preset; spec-correct behaviour applies and no vendor-specific transforms are used.

## Where to configure

Each registered service provider has a **SCIM** tab in its detail page. From there, super admins can set the SCIM target URL, application type, membership mode, sync-log retention, and bearer credentials.

Bearer tokens are shown in plaintext exactly once at creation or rotation time. Save them to your secrets manager immediately. Tokens can be rotated with a configurable overlap window so the old and new credentials are both accepted for a short period.
