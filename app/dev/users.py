#!/usr/bin/env python3
import logging
import uuid

import argh

import database
import utils.password
import utils.validate


def add_super_admin(subdomain: str, email: str, password: str):
    """Create a super admin user with email and password for a tenant."""
    utils.validate.subdomain(subdomain)

    # Get tenant ID from subdomain
    tenant = database.fetchone(
        database.UNSCOPED,
        'select id from tenants where subdomain = :subdomain',
        {'subdomain': subdomain},
    )

    if not tenant:
        raise ValueError(f'Tenant with subdomain {subdomain} not found')

    tenant_id = tenant['id']

    # Check if user with this email already exists
    existing = database.fetchone(
        tenant_id,
        'select user_id from user_emails where email = :email',
        {'email': email},
    )

    if existing:
        logging.info('Super admin user %s already exists for tenant %s', email, subdomain)
        return

    password_hash = utils.password.hash_password(password)

    # Create user
    user = database.fetchone(
        tenant_id,
        '''
        insert into users (tenant_id, first_name, last_name, role, password_hash)
        values (:tenant_id, 'Super', 'Admin', 'super_admin', :password_hash)
        returning id
        ''',
        {'tenant_id': tenant_id, 'password_hash': password_hash},
    )

    if not user:
        raise RuntimeError('Failed to create user')

    user_id = user['id']

    # Create email (primary and verified)
    database.execute(
        tenant_id,
        '''
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, true, now())
        ''',
        {'tenant_id': tenant_id, 'user_id': user_id, 'email': email},
    )

    logging.info('Created super admin user %s for tenant %s', email, subdomain)


if __name__ == '__main__':
    argh.dispatch_command(add_super_admin)

