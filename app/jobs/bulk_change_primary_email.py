"""Bulk change primary email job handlers.

Two handlers:
- Preview (dry-run): computes downstream impact for each proposed change
- Apply (execute): promotes emails and applies IdP dispositions
"""

import logging
from typing import Any

import database
from jobs.registry import register_handler
from services.emails import compute_email_change_impact
from services.event_log import log_event
from utils.email import send_primary_email_changed_notification
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def _user_name(user: dict) -> str:
    first = user.get("first_name", "")
    last = user.get("last_name", "")
    return f"{first} {last}".strip()


@register_handler("bulk_primary_email_preview")
def handle_bulk_primary_email_preview(task: dict) -> dict[str, Any]:
    """Dry-run: compute impact for each user's proposed email change.

    Args:
        task: Dict with id, tenant_id, job_type, payload, created_by.
              payload contains {"items": [{"user_id": str, "new_primary_email": str}, ...]}

    Returns:
        Dict with per-user impact results and summary totals.
    """
    tenant_id = str(task["tenant_id"])
    items = task["payload"]["items"]

    user_results: list[dict] = []
    users_previewed = 0
    users_with_sp_impact = 0
    users_with_routing_change = 0
    preview_errors = 0

    for item in items:
        user_id = item["user_id"]
        new_email = item["new_primary_email"].strip().lower()

        try:
            # Verify user exists
            user = database.users.get_user_by_id(tenant_id, user_id)
            if not user:
                preview_errors += 1
                user_results.append(
                    {
                        "user_id": user_id,
                        "new_email": new_email,
                        "status": "error",
                        "error_reason": "User not found",
                    }
                )
                continue

            # Fetch user emails to find current primary and target secondary
            all_emails = database.user_emails.list_user_emails(tenant_id, user_id)
            current_primary = ""
            target_email = None
            for e in all_emails:
                if e["is_primary"]:
                    current_primary = e["email"]
                if e["email"].lower() == new_email and not e["is_primary"] and e["verified_at"]:
                    target_email = e

            if not target_email:
                preview_errors += 1
                user_results.append(
                    {
                        "user_id": user_id,
                        "user_name": _user_name(user),
                        "current_email": current_primary,
                        "new_email": new_email,
                        "status": "error",
                        "error_reason": "Email is not a verified secondary email for this user",
                    }
                )
                continue

            # Compute impact
            impact = compute_email_change_impact(tenant_id, user_id, new_email)

            users_previewed += 1
            if impact["summary"]["affected_sp_count"] > 0:
                users_with_sp_impact += 1
            if impact["routing_change"]:
                users_with_routing_change += 1

            user_results.append(
                {
                    "user_id": user_id,
                    "user_name": _user_name(user),
                    "current_email": current_primary,
                    "new_email": new_email,
                    "email_id": str(target_email["id"]),
                    "sp_impacts": impact["sp_impacts"],
                    "routing_change": impact["routing_change"],
                    "summary": impact["summary"],
                    "status": "ok",
                }
            )

        except Exception:
            logger.exception("Failed to preview email change for user %s", user_id)
            preview_errors += 1
            user_results.append(
                {
                    "user_id": user_id,
                    "new_email": new_email,
                    "status": "error",
                    "error_reason": "Unexpected error during preview",
                }
            )

    output = (
        f"{users_previewed} previewed, "
        f"{users_with_sp_impact} with SP impact, "
        f"{users_with_routing_change} with routing change, "
        f"{preview_errors} errors"
    )
    logger.info("Bulk primary email preview complete: %s (tenant=%s)", output, tenant_id)

    return {
        "output": output,
        "user_results": user_results,
        "totals": {
            "users_previewed": users_previewed,
            "users_with_sp_impact": users_with_sp_impact,
            "users_with_routing_change": users_with_routing_change,
            "errors": preview_errors,
        },
    }


@register_handler("bulk_primary_email_apply")
def handle_bulk_primary_email_apply(task: dict) -> dict[str, Any]:
    """Execute: promote emails and apply IdP dispositions.

    Args:
        task: Dict with id, tenant_id, job_type, payload, created_by.
              payload contains {"items": [{
                  "user_id": str,
                  "new_primary_email": str,
                  "idp_disposition": "keep"|"switch"|"remove"
              }, ...]}

    Returns:
        Dict with output summary, counts, and per-item details.
    """
    tenant_id = str(task["tenant_id"])
    created_by = str(task["created_by"])
    items = task["payload"]["items"]

    promoted = 0
    skipped = 0
    errors = 0
    details: list[dict[str, str]] = []

    with system_context():
        for item in items:
            user_id = item["user_id"]
            new_email = item["new_primary_email"].strip().lower()
            idp_disposition = item.get("idp_disposition", "keep")

            try:
                # Verify user exists
                user = database.users.get_user_by_id(tenant_id, user_id)
                if not user:
                    errors += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "email": new_email,
                            "status": "error",
                            "reason": "User not found",
                        }
                    )
                    continue

                # Find current primary and target secondary email
                all_emails = database.user_emails.list_user_emails(tenant_id, user_id)
                old_primary = ""
                target_email = None
                for e in all_emails:
                    if e["is_primary"]:
                        old_primary = e["email"]
                    if e["email"].lower() == new_email and not e["is_primary"] and e["verified_at"]:
                        target_email = e

                if not target_email:
                    errors += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "email": new_email,
                            "status": "error",
                            "reason": "Email is not a verified secondary email for this user",
                        }
                    )
                    continue

                email_id = str(target_email["id"])

                # Promote: unset current primary, set new primary
                database.user_emails.unset_primary_emails(tenant_id, user_id)
                database.user_emails.set_primary_email(tenant_id, email_id)

                # Log primary email change event
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=created_by,
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="primary_email_changed",
                    metadata={
                        "email_id": email_id,
                        "email": new_email,
                        "old_email": old_primary,
                        "bulk_operation": True,
                    },
                )

                # Apply IdP disposition
                if idp_disposition == "switch":
                    domain = new_email.split("@")[1] if "@" in new_email else ""
                    domain_idp = (
                        database.saml.get_idp_for_domain(tenant_id, domain) if domain else None
                    )
                    new_idp_id = str(domain_idp["id"]) if domain_idp else None
                    if new_idp_id and domain_idp:
                        database.users.saml_assignment.update_user_saml_idp(
                            tenant_id, user_id, new_idp_id
                        )
                        log_event(
                            tenant_id=tenant_id,
                            actor_user_id=created_by,
                            artifact_type="user",
                            artifact_id=user_id,
                            event_type="user_saml_idp_assigned",
                            metadata={
                                "old_idp": user.get("saml_idp_name", ""),
                                "new_idp": domain_idp.get("name", ""),
                                "bulk_operation": True,
                            },
                        )
                elif idp_disposition == "remove":
                    if user.get("saml_idp_id"):
                        database.users.saml_assignment.update_user_saml_idp(
                            tenant_id, user_id, None
                        )
                        log_event(
                            tenant_id=tenant_id,
                            actor_user_id=created_by,
                            artifact_type="user",
                            artifact_id=user_id,
                            event_type="user_saml_idp_assigned",
                            metadata={
                                "old_idp": user.get("saml_idp_name", ""),
                                "new_idp": "Password authentication",
                                "bulk_operation": True,
                            },
                        )
                # "keep" disposition: no IdP change needed

                # Send notification to old primary email
                if old_primary and old_primary != new_email:
                    try:
                        send_primary_email_changed_notification(
                            old_primary,
                            new_email,
                            "System (bulk operation)",
                            tenant_id=tenant_id,
                        )
                    except Exception:
                        logger.warning("Failed to send notification for user %s", user_id)

                promoted += 1
                details.append(
                    {
                        "user_id": user_id,
                        "email": new_email,
                        "status": "promoted",
                        "reason": f"Primary email changed from {old_primary}",
                    }
                )

            except Exception:
                logger.exception("Failed to change primary email for user %s", user_id)
                errors += 1
                details.append(
                    {
                        "user_id": user_id,
                        "email": new_email,
                        "status": "error",
                        "reason": "Unexpected error",
                    }
                )

    output = f"{promoted} promoted, {skipped} skipped, {errors} errors"
    logger.info("Bulk primary email apply complete: %s (tenant=%s)", output, tenant_id)

    return {
        "output": output,
        "promoted": promoted,
        "skipped": skipped,
        "errors": errors,
        "details": details,
    }
