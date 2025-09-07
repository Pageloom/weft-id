\set ON_ERROR_STOP on

-- Needed for gen_random_uuid()
create extension if not exists pgcrypto;

-- Keep tenants readable for bootstrap/host lookup (NO RLS here)
create table if not exists tenants (
  id         uuid primary key default gen_random_uuid(),
  subdomain  text not null unique check (length(subdomain) <= 63),
  name       text not null default '',
  created_at timestamptz not null default now()
);

-- Helpful index if you frequently look up by subdomain (redundant with UNIQUE, but explicit)
-- create unique index if not exists tenants_subdomain_key on tenants(subdomain);

comment on table tenants is 'Tenant registry. No RLS so host→tenant lookup works before setting app.tenant_id.';
