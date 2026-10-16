-- Administrator connection. Run after 01; changes only this project's new DB.
REVOKE ALL ON DATABASE webguard_hub_dev FROM PUBLIC;
GRANT CONNECT ON DATABASE webguard_hub_dev TO webguard_hub_dev_migrator, webguard_hub_dev_app;
