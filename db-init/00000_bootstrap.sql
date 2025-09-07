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
