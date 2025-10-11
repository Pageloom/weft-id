import uuid

import database


def add_super_admin(tenant_id: uuid.UUID, email: str):
    database.execute(
        tenant_id,
        """
        insert into users (tenant_id, email, first_name, last_name, role)
        values (%(tenant_id)s, %(email)s, 'Super', 'Admin', 'super_admin')
        """,
        {"tenant_id": tenant_id, "email": email},
    )
