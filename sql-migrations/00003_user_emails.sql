-- The user_emails table stores email addresses associated with users.
-- Each email address is unique within a tenant and can be marked as primary.
-- The table includes fields for verification status and a nonce for email verification processes.
-- Row Level Security (RLS) is enabled to ensure that email addresses are
-- only accessible within the context of their tenant, enforced through policies
-- that reference the current_setting('app.tenant_id').
-- This design maintains strict data isolation while allowing for flexible
-- management of user email addresses.
\set ON_ERROR_STOP on

create extension if not exists citext;

do
$$
    begin
        if not exists (select 1
                       from pg_constraint
                       where conrelid = 'public.users'::regclass
                         and contype = 'u'
                         and conname = 'users_id_tenant_unique') then
            alter table public.users
                add constraint users_id_tenant_unique unique (id, tenant_id);
        end if;
    end
$$;

create table if not exists public.user_emails
(
    id           uuid primary key     default gen_random_uuid(),
    tenant_id    uuid        not null,
    user_id      uuid        not null,
    email        citext      not null,
    is_primary   boolean     not null default false,
    verified_at  timestamptz null,
    verify_nonce int         not null default 1,
    created_at   timestamptz not null default now(),

    -- An address must be unique within a tenant
    unique (tenant_id, email),

    -- Composite FK keeps tenant_id consistent with parent user
    constraint fk_user_emails_user_tenant
        foreign key (user_id, tenant_id)
            references public.users (id, tenant_id)
            on delete cascade
);

-- Helpful indexes
create index if not exists idx_user_emails_user_id on public.user_emails (user_id);

-- One primary email per user (partial unique index)
create unique index if not exists user_emails_primary_per_user
    on public.user_emails (user_id)
    where is_primary;

alter table public.user_emails
    enable row level security;

do
$$
    begin
        if not exists (select 1
                       from pg_policies
                       where schemaname = 'public'
                         and tablename = 'user_emails'
                         and policyname = 'user_emails_tenant_isolation') then
            create policy user_emails_tenant_isolation on public.user_emails
                using (tenant_id = current_setting('app.tenant_id', true)::uuid)
                with check (tenant_id = current_setting('app.tenant_id', true)::uuid);
        end if;
    end
$$;

comment on table public.user_emails is
    'Per-user email addresses, scoped by tenant via tenant_id; RLS enforces tenant isolation.';
