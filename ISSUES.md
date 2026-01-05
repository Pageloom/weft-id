# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Activity Logging: OAuth2 client deletion not logged

**Found in:** `app/services/oauth2.py:303-316`
**Severity:** High
**Principle Violated:** Activity Logging
**Description:** The `delete_client` function deletes an OAuth2 client via `database.oauth2.delete_client()` but does not call `log_event()` after the mutation.
**Evidence:**
```python
def delete_client(tenant_id: str, client_id: str) -> int:
    """Delete an OAuth2 client."""
    return database.oauth2.delete_client(tenant_id, client_id)
    # No log_event() call!
```
**Impact:** OAuth2 client deletions are not recorded in the audit log, breaking compliance requirements and making it impossible to track who deleted API clients and when.
**Root Cause:** Oversight - the create functions log events but delete does not.
**Suggested fix:**
```python
def delete_client(tenant_id: str, client_id: str, actor_user_id: str) -> int:
    # Get client info before deletion for logging
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not client:
        return 0

    rows = database.oauth2.delete_client(tenant_id, client_id)

    if rows > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_deleted",
            metadata={"name": client["name"], "client_id": client_id},
            request_metadata=None,
        )

    return rows
```

---

## Activity Logging: OAuth2 client secret regeneration not logged

**Found in:** `app/services/oauth2.py:319-330`
**Severity:** High
**Principle Violated:** Activity Logging
**Description:** The `regenerate_client_secret` function regenerates the secret via `database.oauth2.regenerate_client_secret()` but does not call `log_event()` after the mutation.
**Evidence:**
```python
def regenerate_client_secret(tenant_id: str, client_id: str) -> str:
    """Regenerate the client secret."""
    return database.oauth2.regenerate_client_secret(tenant_id, client_id)
    # No log_event() call!
```
**Impact:** Secret regenerations are security-sensitive operations that should be audited. Without logging, there's no trail of when secrets were rotated or by whom.
**Root Cause:** Oversight - function lacks actor context needed for logging.
**Suggested fix:**
```python
def regenerate_client_secret(tenant_id: str, client_id: str, actor_user_id: str) -> str:
    # Get client info for logging
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)

    new_secret = database.oauth2.regenerate_client_secret(tenant_id, client_id)

    if client:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_secret_regenerated",
            metadata={"name": client["name"], "client_id": client_id},
            request_metadata=None,
        )

    return new_secret
```

---

## Activity Logging: Public email verification not logged

**Found in:** `app/services/emails.py:605-631`
**Severity:** High
**Principle Violated:** Activity Logging
**Description:** The `verify_email_by_nonce` function marks an email as verified via `database.user_emails.verify_email()` but does not call `log_event()` after the mutation. The sister function `verify_email()` at line 423 DOES log the event, making this inconsistent.
**Evidence:**
```python
def verify_email_by_nonce(tenant_id: str, email_id: str, nonce: int) -> bool:
    """Verify an email address using its nonce (public endpoint flow)."""
    email = database.user_emails.get_email_for_verification(tenant_id, email_id)
    if not email or email["verify_nonce"] != nonce:
        return False

    database.user_emails.verify_email(tenant_id, email_id)
    return True  # No log_event() call!
```
**Impact:** Email verifications through the public flow (clicking verification link) are not logged, while the authenticated flow logs them. This creates an inconsistent audit trail.
**Root Cause:** Function predates logging requirement and has no RequestingUser context.
**Suggested fix:**
```python
def verify_email_by_nonce(tenant_id: str, email_id: str, nonce: int) -> bool:
    email = database.user_emails.get_email_for_verification(tenant_id, email_id)
    if not email or email["verify_nonce"] != nonce:
        return False

    database.user_emails.verify_email(tenant_id, email_id)

    # Log using the email owner as the actor
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(email["user_id"]),
        artifact_type="user",
        artifact_id=str(email["user_id"]),
        event_type="email_verified",
        metadata={
            "email_id": email_id,
            "email": email["email"],
            "flow": "public_link",
        },
        request_metadata=None,
    )

    return True
```

---
