"""Row-to-schema conversion helpers for users service.

These private helpers convert database rows to Pydantic schemas.
They are used by multiple modules in the users package.
"""

import database
from schemas.api import (
    EmailInfo,
    UserDetail,
    UserProfile,
    UserSummary,
)
from services.exceptions import NotFoundError


def _user_row_to_profile(user: dict) -> UserProfile:
    """Convert database user dict to UserProfile schema."""
    return UserProfile(
        id=str(user["id"]),
        email=user.get("email", ""),
        first_name=user["first_name"],
        last_name=user["last_name"],
        role=user["role"],
        timezone=user.get("tz"),
        locale=user.get("locale"),
        theme=user.get("theme", "system"),
        mfa_enabled=user.get("mfa_enabled", False),
        mfa_method=user.get("mfa_method"),
        created_at=user["created_at"],
        last_login=user.get("last_login"),
    )


def _user_row_to_summary(user: dict) -> UserSummary:
    """Convert database user dict to UserSummary schema."""
    return UserSummary(
        id=str(user["id"]),
        email=user.get("email"),
        first_name=user["first_name"],
        last_name=user["last_name"],
        role=user["role"],
        created_at=user["created_at"],
        last_login=user.get("last_login"),
        last_activity_at=user.get("last_activity_at"),
        is_inactivated=user.get("is_inactivated", False),
        is_anonymized=user.get("is_anonymized", False),
    )


def _user_row_to_detail(user: dict, emails: list[dict], is_service: bool) -> UserDetail:
    """Convert database user dict to UserDetail schema."""
    email_list = [
        EmailInfo(
            id=str(e["id"]),
            email=e["email"],
            is_primary=e["is_primary"],
            verified_at=e.get("verified_at"),
            created_at=e["created_at"],
        )
        for e in emails
    ]
    return UserDetail(
        id=str(user["id"]),
        email=user.get("email"),
        first_name=user["first_name"],
        last_name=user["last_name"],
        role=user["role"],
        timezone=user.get("tz"),
        locale=user.get("locale"),
        mfa_enabled=user.get("mfa_enabled", False),
        mfa_method=user.get("mfa_method"),
        created_at=user["created_at"],
        last_login=user.get("last_login"),
        emails=email_list,
        is_service_user=is_service,
        is_inactivated=user.get("is_inactivated", False),
        is_anonymized=user.get("is_anonymized", False),
        inactivated_at=user.get("inactivated_at"),
        anonymized_at=user.get("anonymized_at"),
        saml_idp_id=str(user["saml_idp_id"]) if user.get("saml_idp_id") else None,
        saml_idp_name=user.get("saml_idp_name"),
        has_password=user.get("has_password", False),
    )


def _fetch_user_detail(tenant_id: str, user_id: str) -> UserDetail:
    """Fetch a user by ID with emails and service status, returning UserDetail."""
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        user["email"] = primary_email["email"]

    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    is_service = database.users.is_service_user(tenant_id, user_id)

    return _user_row_to_detail(user, emails, is_service)
