/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package mysql implements engine.Engine for MySQL and MariaDB.
package mysql

import (
	"context"
	"crypto/sha1" //nolint:gosec // required by mysql_native_password
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	driver "github.com/go-sql-driver/mysql"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

// Engine is the MySQL / MariaDB engine.
type Engine struct{}

var _ engine.Engine = Engine{}

// SetPassword implements engine.Engine.
//
// MySQL rewrites the password out of ALTER USER before writing it to the general,
// slow and binary logs. MariaDB does not, so for MariaDB the password is sent as
// a mysql_native_password hash instead.
func (Engine) SetPassword(ctx context.Context, ep engine.Endpoint, master engine.Credentials, account engine.Account, password string) error {
	// The master user needs no privilege on the application's database.
	ep.Database = ""
	db, err := open(ep, master)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	host := account.MySQLHost
	if host == "" {
		host = "%"
	}
	var version string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return fmt.Errorf("connect as %q: %w", master.Username, redact(err))
	}

	// Placeholders are interpolated by the driver as properly escaped string
	// literals ('user'@'host' is valid account syntax); ALTER USER cannot be prepared.
	stmt, secret := "ALTER USER ?@? IDENTIFIED BY ?", password
	if strings.Contains(version, "MariaDB") {
		var plugin string
		err := db.QueryRowContext(ctx, "SELECT plugin FROM mysql.user WHERE user = ? AND host = ?", account.Username, host).Scan(&plugin)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("user '%s'@'%s' does not exist", account.Username, host)
		case err != nil:
			return fmt.Errorf("read authentication plugin of '%s'@'%s': %w", account.Username, host, redact(err))
		case plugin != "" && plugin != "mysql_native_password":
			return fmt.Errorf("user '%s'@'%s' uses the %s plugin; only mysql_native_password can be rotated on MariaDB "+
				"without writing the password to the server logs", account.Username, host, plugin)
		}
		stmt, secret = "ALTER USER ?@? IDENTIFIED BY PASSWORD ?", nativePasswordHash(password)
	}
	if _, err := db.ExecContext(ctx, stmt, account.Username, host, secret); err != nil {
		return fmt.Errorf("alter user '%s'@'%s': %w", account.Username, host, redact(err))
	}
	return nil
}

// nativePasswordHash is the mysql_native_password hash: "*" + upper-case hex of SHA1(SHA1(password)).
func nativePasswordHash(password string) string {
	first := sha1.Sum([]byte(password)) //nolint:gosec // the algorithm is defined by the server
	second := sha1.Sum(first[:])        //nolint:gosec // the algorithm is defined by the server
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}

// VerifyLogin implements engine.Engine.
func (Engine) VerifyLogin(ctx context.Context, ep engine.Endpoint, creds engine.Credentials) error {
	db, err := open(ep, creds)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("login as %q: %w", creds.Username, redact(err))
	}
	return nil
}

func open(ep engine.Endpoint, creds engine.Credentials) (*sql.DB, error) {
	tlsCfg, err := engine.TLSConfig(ep)
	if err != nil {
		return nil, err
	}
	cfg := driver.NewConfig()
	cfg.User = creds.Username
	cfg.Passwd = creds.Password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
	cfg.DBName = ep.Database
	cfg.TLS = tlsCfg
	cfg.Timeout = engine.ConnectTimeout
	cfg.ReadTimeout = engine.ConnectTimeout
	cfg.WriteTimeout = engine.ConnectTimeout
	cfg.InterpolateParams = true
	cfg.AllowCleartextPasswords = false
	cfg.AllowFallbackToPlaintext = false

	connector, err := driver.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	return db, nil
}

// redact keeps server errors to their number and message; they never contain
// the password, but the driver's DSN-bearing errors could.
func redact(err error) error {
	if myErr, ok := errors.AsType[*driver.MySQLError](err); ok {
		return fmt.Errorf("%s (error %d)", myErr.Message, myErr.Number)
	}
	return err
}
