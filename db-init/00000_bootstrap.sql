-- ============================================================================
-- Bootstrap database for local dev (Docker init script)
--
-- This file is executed automatically by the official Postgres image on the
-- FIRST initialization of the data directory (everything under
-- /docker-entrypoint-initdb.d). It assumes POSTGRES_DB=appdb so we’re already
-- connected to the target DB when this runs.
--
-- What it sets up:
--   1) Roles
--      - appowner  (NOLOGIN): owns DB/schema/objects; performs DDL.
--      - migrator  (LOGIN)  : runs migrations; can SET ROLE appowner.
--      - appuser   (LOGIN)  : application runtime; DML only; no DDL; NOBYPASSRLS.
--   2) Database & schema ownership
--      - appowner owns the database and public schema.
--      - PUBLIC’s broad rights are revoked (explicit grants only).
--   3) Access for runtime
--      - migrator/appuser can CONNECT to appdb.
--      - appuser can USAGE the public schema.
--      - appowner can CREATE in the public schema.
--   4) Default privileges for future objects
--      - Any objects created by appowner automatically grant DML to appuser.
--   5) Time zone
--      - Database default time zone set to UTC.
--
-- Notes:
--   - RLS policies and tables are created by subsequent migration files.
--   - This script is intended to run once on first boot; re-running it later
--     manually may fail if roles/ownership already exist (that’s fine).
--   - Passwords here are for local development only.
-- ============================================================================
\set ON_ERROR_STOP on

-- roles
CREATE ROLE appowner NOLOGIN NOBYPASSRLS;
CREATE ROLE migrator LOGIN PASSWORD 'migratorpass' NOBYPASSRLS NOSUPERUSER NOCREATEROLE;
CREATE ROLE appuser  LOGIN PASSWORD 'apppass'      NOBYPASSRLS NOSUPERUSER NOCREATEROLE;
GRANT appowner TO migrator;

-- we're already connected to POSTGRES_DB (appdb)
ALTER DATABASE appdb OWNER TO appowner;
ALTER DATABASE appdb SET timezone TO 'UTC';

-- schema ownership & perms
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
