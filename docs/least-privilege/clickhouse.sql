-- ClickHouse, SQL-managed users.
CREATE USER krotos_rotator IDENTIFIED WITH sha256_password BY 'change-me';
GRANT ALTER USER ON *.* TO krotos_rotator;
