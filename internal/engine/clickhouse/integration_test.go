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

package clickhouse

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	tcclickhouse "github.com/testcontainers/testcontainers-go/modules/clickhouse"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
	"github.com/Warewave-Technology/krotos/internal/engine"
	"github.com/Warewave-Technology/krotos/internal/engine/enginetest"
)

var (
	native, http engine.Endpoint
	master       = engine.Credentials{Username: "admin", Password: "admin-password"}
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := tcclickhouse.Run(ctx, "clickhouse/clickhouse-server:25.8",
		tcclickhouse.WithUsername(master.Username),
		tcclickhouse.WithPassword(master.Password),
		tcclickhouse.WithDatabase("orders"),
		// Lets the admin user manage users with SQL.
		testcontainers.WithEnv(map[string]string{"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1"}),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start clickhouse: %v\n", err)
		os.Exit(1)
	}
	native = endpoint(ctx, c, "9000/tcp", "native")
	http = endpoint(ctx, c, "8123/tcp", "http")
	code := m.Run()
	_ = c.Terminate(ctx)
	os.Exit(code)
}

func endpoint(ctx context.Context, c *tcclickhouse.ClickHouseContainer, port, protocol string) engine.Endpoint {
	addr, err := c.PortEndpoint(ctx, port, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "port %s: %v\n", port, err)
		os.Exit(1)
	}
	host, p, _ := net.SplitHostPort(addr)
	portNum, _ := strconv.Atoi(p)
	return engine.Endpoint{
		Host: host, Port: int32(portNum), Database: "orders",
		TLSMode: krotosv1alpha1.TLSModeDisable, ClickHouseProtocol: protocol,
	}
}

func exec(t *testing.T, q string) {
	t.Helper()
	conn, err := connect(native, master)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Exec(t.Context(), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestRotate(t *testing.T) {
	ctx := t.Context()
	e := Engine{}
	cases := []struct {
		user string
		ep   engine.Endpoint
	}{
		{"orders_app", native},
		{"http_app", http},
		{"we`ird user", native},
	}
	for _, tc := range cases {
		t.Run(tc.user, func(t *testing.T) {
			q := quoteIdentifier(tc.user)
			exec(t, "CREATE USER "+q+" IDENTIFIED WITH sha256_password BY 'old-password'")
			exec(t, "GRANT SELECT ON orders.* TO "+q)

			if err := e.VerifyLogin(ctx, tc.ep, engine.Credentials{Username: tc.user, Password: "old-password"}); err != nil {
				t.Fatalf("login with old password: %v", err)
			}
			newPassword := `N3w'pass"\(0)[x]{y}~^;,.<>=_+*|`
			if err := e.SetPassword(ctx, tc.ep, master, engine.Account{Username: tc.user}, newPassword); err != nil {
				t.Fatalf("SetPassword: %v", err)
			}
			if err := e.VerifyLogin(ctx, tc.ep, engine.Credentials{Username: tc.user, Password: newPassword}); err != nil {
				t.Fatalf("login with new password: %v", err)
			}
			err := e.VerifyLogin(ctx, tc.ep, engine.Credentials{Username: tc.user, Password: "old-password"})
			if err == nil {
				t.Fatal("old password still works")
			}
			if strings.Contains(err.Error(), "old-password") {
				t.Fatalf("error leaks password: %v", err)
			}
		})
	}
}

func TestSetPasswordErrors(t *testing.T) {
	ctx := t.Context()
	e := Engine{}

	if err := e.SetPassword(ctx, native, master, engine.Account{Username: "nobody"}, "Some-Password-123"); err == nil {
		t.Fatal("missing user accepted")
	}

	// The admin user is defined in a config file, not by SQL: it cannot be rotated.
	err := e.SetPassword(ctx, native, master, engine.Account{Username: master.Username}, "Some-Password-123")
	if err == nil {
		t.Fatal("config-defined user accepted")
	}
	t.Logf("config-defined user: %v", err)

	wrong := engine.Credentials{Username: master.Username, Password: "wrong-admin-pw"}
	err = e.SetPassword(ctx, native, wrong, engine.Account{Username: "orders_app"}, "Some-Password-123")
	if err == nil || strings.Contains(err.Error(), "wrong-admin-pw") {
		t.Fatalf("wrong master: err = %v", err)
	}
}

func TestPasswordNotLogged(t *testing.T) {
	ctx := t.Context()
	exec(t, "CREATE USER log_check IDENTIFIED WITH sha256_password BY 'initial'")
	const secret = "Very-Secret-Rotated-Password-42"
	if err := (Engine{}).SetPassword(ctx, native, master, engine.Account{Username: "log_check"}, secret); err != nil {
		t.Fatal(err)
	}
	exec(t, "SYSTEM FLUSH LOGS")

	conn, err := connect(native, master)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Read the whole log and search it here: a query containing the secret would itself be logged.
	rows, err := conn.Query(ctx, "SELECT query FROM system.query_log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var alters int
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(q, "ALTER USER") && strings.Contains(q, "log_check") {
			alters++
		}
		if strings.Contains(q, secret) {
			t.Fatalf("query_log contains the plain password: %q", q)
		}
	}
	if alters == 0 {
		t.Fatal("ALTER USER not in query_log; the check would be meaningless")
	}
}

// The README's least-privilege template must be enough to rotate.
func TestLeastPrivilegeTemplate(t *testing.T) {
	ctx := t.Context()
	exec(t, "CREATE USER lp_app IDENTIFIED WITH sha256_password BY 'old-password'")
	exec(t, "GRANT SELECT ON orders.* TO lp_app")
	stmts, err := enginetest.SQLStatements("clickhouse.sql", "lp_app", "rotator-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		exec(t, s)
	}
	rotator := engine.Credentials{Username: enginetest.RotatorUser, Password: "rotator-password"}
	e := Engine{}
	if err := e.SetPassword(ctx, native, rotator, engine.Account{Username: "lp_app"}, "Rotated-By-Least-Privilege-1"); err != nil {
		t.Fatalf("rotate with the template's user: %v", err)
	}
	if err := e.VerifyLogin(ctx, native, engine.Credentials{Username: "lp_app", Password: "Rotated-By-Least-Privilege-1"}); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}
