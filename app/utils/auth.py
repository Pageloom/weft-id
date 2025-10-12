"""Authentication utilities for login and session management."""

from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse

import database
from dependencies import get_tenant_id_from_request
from utils.password import verify_password


def verify_login(tenant_id: str, email: str, password: str) -> dict | None:
    """
    Verify email and password for a user within a tenant.
    Returns user dict if valid, None otherwise.
    Updates last_login timestamp on success.
    """
    # Find user by email within tenant
    user_email = database.fetchone(
        tenant_id,
        '''
        select ue.user_id, u.password_hash
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email and ue.verified_at is not null
        ''',
        {'email': email},
    )

    if not user_email or not user_email['password_hash']:
        return None

    # Verify password
    if not verify_password(user_email['password_hash'], password):
        return None

    user_id = user_email['user_id']

    # Update last_login
    database.execute(
        tenant_id,
        'update users set last_login = now() where id = :user_id',
        {'user_id': user_id},
    )

    # Fetch and return full user record (including MFA fields)
    user = database.fetchone(
        tenant_id,
        '''
        select id, tenant_id, first_name, last_name, role, created_at, last_login,
               mfa_enabled, mfa_method, tz
        from users
        where id = :user_id
        ''',
        {'user_id': user_id},
    )

    return user


def get_current_user(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
) -> dict | None:
    """
    Get the currently authenticated user from session.
    Returns user dict if authenticated, None otherwise.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return None

    user = database.fetchone(
        tenant_id,
        '''
        select id, tenant_id, first_name, last_name, role, created_at, last_login,
               mfa_enabled, mfa_method, tz
        from users
        where id = :user_id
        ''',
        {'user_id': user_id},
    )

    return user


def require_auth(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
) -> dict:
    """
    Require authentication. Redirects to /login if not authenticated.
    Returns user dict if authenticated.
    """
    user = get_current_user(request, tenant_id)
    if not user:
        return RedirectResponse(url='/login', status_code=303)
    return user
