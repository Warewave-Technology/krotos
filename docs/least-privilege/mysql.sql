-- MySQL 8.0 and later.
CREATE USER 'krotos_rotator'@'%' IDENTIFIED BY 'change-me';
GRANT CREATE USER ON *.* TO 'krotos_rotator'@'%';
