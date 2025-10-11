-- The users table represents individual users within a tenant.
-- Each user has a role that defines their permissions within the tenant context.
-- The role is implemented as an enum type with values 'super_admin', 'admin', and 'member'.
-- Row Level Security (RLS) is enabled to ensure that users can only access
-- data associated with their tenant, enforced through policies that reference
-- the current_setting('app.tenant_id').
-- This design ensures strict data isolation between tenants while allowing
-- for flexible user management within each tenant.
\set ON_ERROR_STOP on

do
$$
    begin
        if not exists (select 1 from pg_type where typname = 'user_role') then
            create type user_role as enum ('super_admin','admin','member');
        end if;
    end
$$;

create table if not exists users
(
    id            uuid primary key     default gen_random_uuid(),
    tenant_id     uuid        not null references tenants (id) on delete cascade,
    first_name    text        not null check (length(first_name) <= 200),
    last_name     text        not null check (length(last_name) <= 200),
    role          user_role   not null default 'member',
    created_at    timestamptz not null default now(),
    last_login    timestamptz null,
    password_hash text        null check (
        password_hash is null or char_length(password_hash) between 60 and 255
        )
);

create index if not exists idx_users_tenant on users (tenant_id);
create index if not exists idx_users_tenant_role on users (tenant_id, role);

alter table users
    enable row level security;

do
$$
    begin
        if not exists (select 1
                       from pg_policies
                       where schemaname = 'public'
                         and tablename = 'users'
                         and policyname = 'users_tenant_isolation') then
            create policy users_tenant_isolation on users
                using (tenant_id = current_setting('app.tenant_id', true)::uuid)
                with check (tenant_id = current_setting('app.tenant_id', true)::uuid);
        end if;
    end
$$;

comment on table users is 'Users scoped by tenant via RLS (app.tenant_id).';
