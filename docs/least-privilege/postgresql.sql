-- PostgreSQL 16 and later.
CREATE ROLE krotos_rotator LOGIN CREATEROLE PASSWORD 'change-me';
-- ADMIN on the rotated role is what lets the rotator change its password.
-- INHERIT FALSE and SET FALSE keep the rotator from using that role's privileges.
GRANT orders_app TO krotos_rotator WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
