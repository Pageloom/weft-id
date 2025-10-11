"""Authentication routes for login/logout."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from dependencies import get_tenant_id_from_request
from utils.auth import get_current_user, verify_login

router = APIRouter(prefix='', tags=['auth'])
templates = Jinja2Templates(directory='templates')


@router.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    """Render login page."""
    # If already authenticated, redirect to dashboard
    user = get_current_user(request, get_tenant_id_from_request(request))
    if user:
        return RedirectResponse(url='/dashboard', status_code=303)

    return templates.TemplateResponse('login.html', {'request': request})


@router.post('/login')
def login(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    """Handle login form submission."""
    user = verify_login(tenant_id, email, password)

    if not user:
        return templates.TemplateResponse(
            'login.html', {'request': request, 'error': 'Invalid email or password'}
        )

    # Store user_id in session
    request.session['user_id'] = str(user['id'])

    return RedirectResponse(url='/dashboard', status_code=303)


@router.post('/logout')
def logout(request: Request):
    """Handle logout."""
    request.session.clear()
    return RedirectResponse(url='/login', status_code=303)


@router.get('/dashboard', response_class=HTMLResponse)
def dashboard(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Render dashboard for authenticated users."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url='/login', status_code=303)

    # Fetch user's primary email for display
    import database

    email_row = database.fetchone(
        tenant_id, 'select email from user_emails where user_id = :user_id and is_primary = true', {'user_id': user['id']}
    )

    user['email'] = email_row['email'] if email_row else 'N/A'

    return templates.TemplateResponse('dashboard.html', {'request': request, 'user': user})
