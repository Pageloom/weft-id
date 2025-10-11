"""User management routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from dependencies import get_tenant_id_from_request
from utils.auth import get_current_user
from utils.template_context import get_template_context

router = APIRouter(prefix='/users', tags=['users'])
templates = Jinja2Templates(directory='templates')


@router.get('', response_class=HTMLResponse)
def users_list(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Display list of users in the tenant."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url='/login', status_code=303)

    # Fetch all users in tenant with their primary email
    users = database.fetchall(
        tenant_id,
        '''
        select u.id, u.first_name, u.last_name, u.role, u.created_at, u.last_login,
               ue.email
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        order by u.created_at desc
        ''',
    )

    return templates.TemplateResponse('users_list.html', get_template_context(request, tenant_id, users=users))
