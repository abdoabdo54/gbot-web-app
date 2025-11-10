-- DANGER: This will drop DNS-related tables if they exist.
-- Run against your production database after backup.
DROP TABLE IF EXISTS namecheap_config;
DROP TABLE IF EXISTS dns_record;
DROP TABLE IF EXISTS google_verification;
