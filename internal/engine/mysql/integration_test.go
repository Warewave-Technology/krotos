//go:build integration

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

package mysql

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"strings"
	"testing"

	driver "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	tcmariadb "github.com/testcontainers/testcontainers-go/modules/mariadb"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/engine"
)

const rootPassword = "root-password"

type server struct {
	name     string
	endpoint engine.Endpoint
}

var master = engine.Credentials{Username: "root", Password: rootPassword}

// logArgs turns on the general query log, written to a table the test can read.
var logArgs = testcontainers.WithCmdArgs("--general-log=1", "--log-output=TABLE")

func startServers(t *testing.T) []server {
	t.Helper()
	ctx := context.Background()

	my, err := tcmysql.Run(ctx, "mysql:8.4",
		tcmysql.WithDatabase("orders"), tcmysql.WithUsername("root"), tcmysql.WithPassword(rootPassword), logArgs)
	if err != nil {
		t.Fatalf("start mysql: %v", err)
	}
	t.Cleanup(func() { _ = my.Terminate(ctx) })
	myDSN, err := my.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}

	maria, err := tcmariadb.Run(ctx, "mariadb:11.4",
		tcmariadb.WithDatabase("orders"), tcmariadb.WithUsername("root"), tcmariadb.WithPassword(rootPassword), logArgs)
	if err != nil {
		t.Fatalf("start mariadb: %v", err)
	}
	t.Cleanup(func() { _ = maria.Terminate(ctx) })
	mariaDSN, err := maria.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}

	return []server{
		{"mysql-8.4", endpointFromDSN(t, myDSN)},
		{"mariadb-11.4", endpointFromDSN(t, mariaDSN)},
	}
}

func endpointFromDSN(t *testing.T, dsn string) engine.Endpoint {
	t.Helper()
	cfg, err := driver.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return engine.Endpoint{Host: host, Port: int32(p), Database: "orders", TLSMode: krotosv1alpha1.TLSModeRequire}
}

func rootDB(t *testing.T, ep engine.Endpoint) *sql.DB {
	t.Helper()
	db, err := open(ep, master)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func authString(t *testing.T, db *sql.DB, user, host string) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(t.Context(),
		"SELECT authentication_string FROM mysql.user WHERE user = ? AND host = ?", user, host).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMySQLAndMariaDB(t *testing.T) {
	for _, srv := range startServers(t) {
		t.Run(srv.name, func(t *testing.T) {
			ctx := t.Context()
			e := Engine{}
			ep := srv.endpoint
			db := rootDB(t, ep)

			for _, user := range []string{"orders_app", `we'ird"user`} {
				t.Run(user, func(t *testing.T) {
					exec(t, db, "CREATE USER ?@'%' IDENTIFIED BY 'old-password'", user)
					exec(t, db, "GRANT SELECT ON orders.* TO ?@'%'", user)
					exec(t, db, "CREATE USER ?@'localhost' IDENTIFIED BY 'local-password'", user)
					localBefore := authString(t, db, user, "localhost")

					newPassword := `N3w'pass"\(0)[x]{y}~^;,.<>=_+*|`
					if err := e.SetPassword(ctx, ep, master, engine.Account{Username: user, MySQLHost: "%"}, newPassword); err != nil {
						t.Fatalf("SetPassword: %v", err)
					}
					if err := e.VerifyLogin(ctx, ep, engine.Credentials{Username: user, Password: newPassword}); err != nil {
						t.Fatalf("login with new password: %v", err)
					}
					err := e.VerifyLogin(ctx, ep, engine.Credentials{Username: user, Password: "old-password"})
					if err == nil {
						t.Fatal("old password still works")
					}
					if strings.Contains(err.Error(), "old-password") {
						t.Fatalf("error leaks password: %v", err)
					}
					if authString(t, db, user, "localhost") != localBefore {
						t.Fatal("the 'localhost' account was changed; only '%' was targeted")
					}
				})
			}

			t.Run("errors", func(t *testing.T) {
				err := e.SetPassword(ctx, ep, master, engine.Account{Username: "nobody", MySQLHost: "%"}, "Some-Password-123")
				if err == nil {
					t.Fatal("missing user accepted")
				}
				wrong := engine.Credentials{Username: "root", Password: "wrong-root-pw"}
				err = e.SetPassword(ctx, ep, wrong, engine.Account{Username: "orders_app", MySQLHost: "%"}, "Some-Password-123")
				if err == nil || strings.Contains(err.Error(), "wrong-root-pw") {
					t.Fatalf("wrong master: err = %v", err)
				}
			})

			t.Run("without TLS", func(t *testing.T) {
				plain := ep
				plain.TLSMode = krotosv1alpha1.TLSModeDisable
				exec(t, db, "CREATE USER 'plain_app'@'%' IDENTIFIED BY 'old-password'")
				exec(t, db, "GRANT SELECT ON orders.* TO 'plain_app'@'%'")
				if err := e.SetPassword(ctx, plain, master, engine.Account{Username: "plain_app", MySQLHost: "%"}, "Plain-New-Password-1"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				if err := e.VerifyLogin(ctx, plain, engine.Credentials{Username: "plain_app", Password: "Plain-New-Password-1"}); err != nil {
					t.Fatalf("login: %v", err)
				}
			})

			if strings.HasPrefix(srv.name, "mariadb") {
				t.Run("non-native plugin is refused", func(t *testing.T) {
					exec(t, db, "INSTALL SONAME 'auth_ed25519'")
					exec(t, db, "CREATE USER 'ed_app'@'%' IDENTIFIED VIA ed25519 USING PASSWORD('old-password')")
					err := e.SetPassword(ctx, ep, master, engine.Account{Username: "ed_app", MySQLHost: "%"}, "Some-Password-123")
					if err == nil || !strings.Contains(err.Error(), "ed25519") {
						t.Fatalf("err = %v, want a refusal naming the plugin", err)
					}
				})
			}

			t.Run("password not logged", func(t *testing.T) {
				exec(t, db, "CREATE USER 'log_check'@'%' IDENTIFIED BY 'initial'")
				const secret = "Very-Secret-Rotated-Password-42"
				if err := e.SetPassword(ctx, ep, master, engine.Account{Username: "log_check", MySQLHost: "%"}, secret); err != nil {
					t.Fatal(err)
				}
				// Read the whole log and search it here: a query containing the
				// secret would itself end up in the log.
				rows, err := db.QueryContext(ctx, "SELECT CAST(argument AS CHAR) FROM mysql.general_log")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = rows.Close() }()
				var alters int
				for rows.Next() {
					var arg string
					if err := rows.Scan(&arg); err != nil {
						t.Fatal(err)
					}
					if strings.Contains(arg, "ALTER USER") && strings.Contains(arg, "log_check") {
						alters++
					}
					if strings.Contains(arg, secret) {
						t.Fatalf("general log contains the plain password: %q", arg)
					}
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				if alters == 0 {
					t.Fatal("ALTER USER not in the general log; the check would be meaningless")
				}
			})
		})
	}
}
