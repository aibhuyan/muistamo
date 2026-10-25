-- Development only: runs once, when the dev PostgreSQL volume is first created.
-- muistamo_app holds the server's privileges (granted by migrations); muistamo_server is the
-- login the dev server uses. Production roles and credentials are provisioned separately.
CREATE ROLE muistamo_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE muistamo_server LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'dev-only-not-a-secret' IN ROLE muistamo_app;
