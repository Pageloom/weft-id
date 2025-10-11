-- ============================================================================
-- Bootstrap database for local dev (Docker init script)
--
-- This file is executed automatically by the official Postgres image on the
-- FIRST initialization of the data directory (everything under
-- /docker-entrypoint-initdb.d). It assumes POSTGRES_DB=appdb so we're already
-- connected to the target DB when this runs.
--
-- What it sets up:
--   1) Roles
--      - appowner  (NOLOGIN): owns DB/schema/objects; performs DDL.
--      - migrator  (LOGIN)  : can SET ROLE appowner (kept for future use).
--      - appuser   (LOGIN)  : application runtime; DML only; no DDL; NOBYPASSRLS.
--   2) Database & schema ownership
--      - appowner owns the database and public schema.
--      - PUBLIC's broad rights are revoked (explicit grants only).
--   3) Access for runtime
--      - migrator/appuser can CONNECT to appdb.
--      - appuser can USAGE the public schema.
--      - appowner can CREATE in the public schema.
--   4) Default privileges for future objects
--      - Any objects created by appowner automatically grant DML to appuser.
--   5) Time zone
--      - Database default time zone set to UTC.
--   6) Extensions
--      - pgcrypto for UUID generation
--      - citext for case-insensitive text
--   7) Tables & schema
--      - Multi-tenant structure with RLS policies
--      - tenants, users, user_emails tables
--
-- Notes:
--   - This script runs once on first boot; to rerun, wipe the dbdata volume.
--   - Passwords here are for local development only.
-- ============================================================================
\set ON_ERROR_STOP on

-- ============================================================================
-- ROLES
-- ============================================================================
CREATE ROLE appowner NOLOGIN NOBYPASSRLS;
CREATE ROLE migrator LOGIN PASSWORD 'migratorpass' NOBYPASSRLS NOSUPERUSER NOCREATEROLE;
CREATE ROLE appuser  LOGIN PASSWORD 'apppass'      NOBYPASSRLS NOSUPERUSER NOCREATEROLE;
GRANT appowner TO migrator;

-- we're already connected to POSTGRES_DB (appdb)
ALTER DATABASE appdb OWNER TO appowner;
ALTER DATABASE appdb SET timezone TO 'UTC';

-- ============================================================================
-- SCHEMA OWNERSHIP & PERMISSIONS
-- ============================================================================
ALTER SCHEMA public OWNER TO appowner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL    ON DATABASE appdb   FROM PUBLIC;

GRANT CONNECT ON DATABASE appdb TO migrator, appuser;
GRANT USAGE   ON SCHEMA  public  TO appuser;
GRANT CREATE  ON SCHEMA  public  TO appowner;

-- default DML grants for future objects created by appowner
ALTER DEFAULT PRIVILEGES FOR ROLE appowner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES   TO appuser;
ALTER DEFAULT PRIVILEGES FOR ROLE appowner IN SCHEMA public
  GRANT USAGE, SELECT               ON SEQUENCES TO appuser;

-- ============================================================================
-- EXTENSIONS
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ============================================================================
-- TYPES
-- ============================================================================
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
            CREATE TYPE user_role AS ENUM ('super_admin','admin','member');
        END IF;
    END
$$;

-- ============================================================================
-- TABLES
-- ============================================================================

-- The tenants table is the fundamental building block for multi-tenancy.
-- It is intentionally kept simple to allow for flexible usage patterns.
-- Each tenant is identified by a unique subdomain (e.g. acme.example.com).
-- Once the tenant is identified, subsequent queries to other tables
-- can be scoped using RLS policies based on the tenant_id.
-- This approach allows for a clear separation of data between tenants
-- while maintaining the ability to easily look up tenants by their subdomain.
CREATE TABLE IF NOT EXISTS tenants
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    subdomain  TEXT        NOT NULL UNIQUE CHECK (length(subdomain) <= 63),
    name       TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenants IS 'Tenant registry. No RLS so subdomain→tenant lookup works before setting app.tenant_id.';

-- The users table represents individual users within a tenant.
-- Each user has a role that defines their permissions within the tenant context.
-- The role is implemented as an enum type with values 'super_admin', 'admin', and 'member'.
-- Row Level Security (RLS) is enabled to ensure that users can only access
-- data associated with their tenant, enforced through policies that reference
-- the current_setting('app.tenant_id').
-- This design ensures strict data isolation between tenants while allowing
-- for flexible user management within each tenant.
CREATE TABLE IF NOT EXISTS users
(
    id            UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    first_name    TEXT        NOT NULL CHECK (length(first_name) <= 200),
    last_name     TEXT        NOT NULL CHECK (length(last_name) <= 200),
    role          user_role   NOT NULL DEFAULT 'member',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login    TIMESTAMPTZ NULL,
    password_hash TEXT        NULL CHECK (
        password_hash IS NULL OR char_length(password_hash) BETWEEN 60 AND 255
        )
);

COMMENT ON TABLE users IS 'Users scoped by tenant via RLS (app.tenant_id).';

-- The user_emails table stores email addresses associated with users.
-- Each email address is unique within a tenant and can be marked as primary.
-- The table includes fields for verification status and a nonce for email verification processes.
-- Row Level Security (RLS) is enabled to ensure that email addresses are
-- only accessible within the context of their tenant, enforced through policies
-- that reference the current_setting('app.tenant_id').
-- This design maintains strict data isolation while allowing for flexible
-- management of user email addresses.

-- Add composite unique constraint to users for FK reference from user_emails
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_constraint
                       WHERE conrelid = 'public.users'::regclass
                         AND contype = 'u'
                         AND conname = 'users_id_tenant_unique') THEN
            ALTER TABLE public.users
                ADD CONSTRAINT users_id_tenant_unique UNIQUE (id, tenant_id);
        END IF;
    END
$$;

CREATE TABLE IF NOT EXISTS public.user_emails
(
    id           UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL,
    user_id      UUID        NOT NULL,
    email        CITEXT      NOT NULL,
    is_primary   BOOLEAN     NOT NULL DEFAULT false,
    verified_at  TIMESTAMPTZ NULL,
    verify_nonce INT         NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- An address must be unique within a tenant
    UNIQUE (tenant_id, email),

    -- Composite FK keeps tenant_id consistent with parent user
    CONSTRAINT fk_user_emails_user_tenant
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES public.users (id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE public.user_emails IS
    'Per-user email addresses, scoped by tenant via tenant_id; RLS enforces tenant isolation.';

-- ============================================================================
-- INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users (tenant_id, role);
CREATE INDEX IF NOT EXISTS idx_user_emails_user_id ON public.user_emails (user_id);

-- One primary email per user (partial unique index)
CREATE UNIQUE INDEX IF NOT EXISTS user_emails_primary_per_user
    ON public.user_emails (user_id)
    WHERE is_primary;

-- ============================================================================
-- EXPLICIT GRANTS (for tables created in this script)
-- ============================================================================
-- The ALTER DEFAULT PRIVILEGES above only applies to *future* tables.
-- We need to explicitly grant on tables created in this script.

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenants TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE user_emails TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'users'
                         AND policyname = 'users_tenant_isolation') THEN
            CREATE POLICY users_tenant_isolation ON users
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

-- Enable RLS on user_emails table
ALTER TABLE public.user_emails ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'user_emails'
                         AND policyname = 'user_emails_tenant_isolation') THEN
            CREATE POLICY user_emails_tenant_isolation ON public.user_emails
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;
