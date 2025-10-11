-- The tenants table is the fundamental building block for multi-tenacy.
-- It is intentionally kept simple to allow for flexible usage patterns.
-- Each tenant is identified by a unique subdomain (e.g. acme.example.com).
-- Once the tenant is identified, subsequent queries to other tables
-- can be scoped using RLS policies based on the tenant_id.
-- This approach allows for a clear separation of data between tenants
-- while maintaining the ability to easily look up tenants by their subdomain.
\set ON_ERROR_STOP on

create extension if not exists pgcrypto;

create table if not exists tenants
(
    id         uuid primary key     default gen_random_uuid(),
    subdomain  text        not null unique check (length(subdomain) <= 63),
    name       text        not null default '',
    created_at timestamptz not null default now()
);

comment on table tenants is 'Tenant registry. No RLS so subdomain→tenant lookup works before setting app.tenant_id.';
