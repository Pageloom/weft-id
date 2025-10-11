"""User settings routes (profile, emails, MFA)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from dependencies import get_tenant_id_from_request
from utils.auth import get_current_user

router = APIRouter(prefix='/settings', tags=['settings'])
templates = Jinja2Templates(directory='templates')


@router.get('/profile', response_class=HTMLResponse)
def profile_settings(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Display and edit user profile settings (name, etc)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url='/login', status_code=303)

    return templates.TemplateResponse('settings_profile.html', {'request': request, 'user': user})


@router.get('/emails', response_class=HTMLResponse)
def email_settings(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Display and manage user email addresses."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url='/login', status_code=303)

    # Fetch all email addresses for this user
    emails = database.fetchall(
        tenant_id,
        '''
        select id, email, is_primary, is_verified, created_at
        from user_emails
        where user_id = :user_id
        order by is_primary desc, created_at asc
        ''',
        {'user_id': user['id']},
    )

    return templates.TemplateResponse('settings_emails.html', {'request': request, 'user': user, 'emails': emails})


@router.get('/mfa', response_class=HTMLResponse)
def mfa_settings(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Display and configure MFA settings."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url='/login', status_code=303)

    # Check if user has backup codes
    backup_codes = database.fetchall(
        tenant_id,
        'select id, code, used_at from mfa_backup_codes where user_id = :user_id order by created_at asc',
        {'user_id': user['id']},
    )

    return templates.TemplateResponse(
        'settings_mfa.html',
        {
            'request': request,
            'user': user,
            'mfa_method': user.get('mfa_method', 'email'),
            'backup_codes': backup_codes,
        },
    )
