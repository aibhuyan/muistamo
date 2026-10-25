-- Development only: runs once, when the dev PostgreSQL volume is first created.
-- muistamo_app holds the server's privileges (granted by migrations); muistamo_server is the
-- login the dev server uses. Production roles and credentials are provisioned separately.
CREATE ROLE muistamo_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE muistamo_server LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'dev-only-not-a-secret' IN ROLE muistamo_app;
-- The knowledge service's roles: muistamo_knowledge_app holds its privileges on the knowledge
-- schema only (granted by knowledge migrations); muistamo_knowledge_server is its dev login.
CREATE ROLE muistamo_knowledge_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE muistamo_knowledge_server LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'dev-only-not-a-secret' IN ROLE muistamo_knowledge_app;
