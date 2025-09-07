\set ON_ERROR_STOP on

-- case-insensitive email per-tenant
create extension if not exists citext;

-- role enum (create once)
do $$
begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type user_role as enum ('super_admin','admin','member');
  end if;
end $$;

-- users table
create table if not exists users (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references tenants(id) on delete cascade,
  email      citext not null,
  first_name text not null check (length(first_name) <= 200),
  last_name  text not null check (length(last_name)  <= 200),
  role       user_role not null default 'member',
  created_at timestamptz not null default now(),
  last_login timestamptz null,
  unique (tenant_id, email)  -- email unique within a tenant (case-insensitive via citext)
);

-- indexes (safe if already exist)
create index if not exists idx_users_tenant        on users(tenant_id);
create index if not exists idx_users_tenant_role   on users(tenant_id, role);

-- Row Level Security: enabled (no FORCE needed since appuser isn't owner)
alter table users enable row level security;

-- Policy: create if missing
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'users' and policyname = 'users_tenant_isolation'
  ) then
    create policy users_tenant_isolation on users
      using (tenant_id = current_setting('app.tenant_id', true)::uuid)
      with check (tenant_id = current_setting('app.tenant_id', true)::uuid);
  end if;
end $$;

comment on table users is 'Users scoped by tenant via RLS (app.tenant_id).';
