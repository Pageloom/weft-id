import uuid
import sql

def add_super_admin(tenant_id: uuid.UUID, email :str):
    sql.execute(
        tenant_id,
        '''
        insert into users (tenant_id, email, first_name, last_name, role)
        values (%(tenant_ids)s, %(email)s, 'Super', 'Admin', 'super_admin')
        ''', {
            'tenant_id': tenant_id,
            'email': email
        }
    )



