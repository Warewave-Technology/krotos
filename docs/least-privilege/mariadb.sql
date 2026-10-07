-- MariaDB 10.4 and later.
CREATE USER 'krotos_rotator'@'%' IDENTIFIED BY 'change-me';
GRANT CREATE USER ON *.* TO 'krotos_rotator'@'%';
-- Only these columns: enough to check the account's authentication plugin,
-- without access to password hashes.
GRANT SELECT (User, Host, plugin) ON mysql.user TO 'krotos_rotator'@'%';
