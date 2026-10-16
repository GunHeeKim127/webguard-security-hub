-- DBeaver: connect to postgres as administrator. Run this block once.
-- No passwords in this file. Set each password using DBeaver's role editor.
DO $$
BEGIN
 IF EXISTS (SELECT FROM pg_roles WHERE rolname IN ('webguard_hub_dev_migrator','webguard_hub_dev_app')) THEN
  RAISE EXCEPTION 'Project role already exists. Stop and inspect; never overwrite another project role.';
 END IF;
 CREATE ROLE webguard_hub_dev_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 CREATE ROLE webguard_hub_dev_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END $$;
