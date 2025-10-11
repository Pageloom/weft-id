#!/usr/bin/env python3
import logging
import time
import uuid

import argh
import psycopg.errors

import database
import utils.validate


def add_super_admin(tenant_id: uuid.UUID, email: str):
    database.execute(
        tenant_id,
        '''
        insert into users (tenant_id, first_name, last_name, role)
        values (:tenant_id, 'Super', 'Admin', 'super_admin')
        ''',
        {'tenant_id': tenant_id, 'email': email},
    )

