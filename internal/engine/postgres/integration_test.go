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

package postgres

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

const (
	postgresImage  = "postgres:17-alpine"
	masterUser     = "master"
	masterPassword = "master-password"
	database       = "orders"
)

var (
	container *tcpostgres.PostgresContainer
	endpoint  engine.Endpoint
	master    = engine.Credentials{Username: masterUser, Password: masterPassword}
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	container, err = tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(database),
		tcpostgres.WithUsername(masterUser),
		tcpostgres.WithPassword(masterPassword),
		tcpostgres.BasicWaitStrategies(),
		// Log every statement so the test can check that no password is logged.
		testcontainers.WithCmdArgs("-c", "log_statement=all"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start postgres: %v\n", err)
		os.Exit(1)
	}
	dsn, err := container.ConnectionString(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection string: %v\n", err)
		os.Exit(1)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse dsn: %v\n", err)
		os.Exit(1)
	}
	endpoint = engine.Endpoint{Host: cfg.Host, Port: int32(cfg.Port), Database: database}

	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func createRole(t *testing.T, name, password string) {
	t.Helper()
	ctx := t.Context()
	conn, err := connect(ctx, endpoint, master)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn(conn)
	_, err = conn.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s",
		pgx.Identifier{name}.Sanitize(), quoteLiteral(password)))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRotate(t *testing.T) {
	ctx := t.Context()
	e := Engine{}
	for _, user := range []string{"orders_app", `weird "user" name`} {
		t.Run(user, func(t *testing.T) {
			createRole(t, user, "old-password")
			oldCreds := engine.Credentials{Username: user, Password: "old-password"}
			newCreds := engine.Credentials{Username: user, Password: "N3w!pass-(0)[x]{y}~^;,.<>=_+*|"}

			if err := e.VerifyLogin(ctx, endpoint, oldCreds); err != nil {
				t.Fatalf("login with old password: %v", err)
			}
			if err := e.SetPassword(ctx, endpoint, master, engine.Account{Username: user}, newCreds.Password); err != nil {
				t.Fatalf("SetPassword: %v", err)
			}
			if err := e.VerifyLogin(ctx, endpoint, newCreds); err != nil {
				t.Fatalf("login with new password: %v", err)
			}
			err := e.VerifyLogin(ctx, endpoint, oldCreds)
			if err == nil {
				t.Fatal("old password still works")
			}
			if strings.Contains(err.Error(), oldCreds.Password) {
				t.Fatalf("error leaks password: %v", err)
			}
		})
	}
}

func TestSetPasswordErrors(t *testing.T) {
	ctx := t.Context()
	e := Engine{}

	err := e.SetPassword(ctx, endpoint, master, engine.Account{Username: "does_not_exist"}, "Some-Password-123")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing role: err = %v", err)
	}

	wrongMaster := engine.Credentials{Username: masterUser, Password: "wrong-master-pw"}
	err = e.SetPassword(ctx, endpoint, wrongMaster, engine.Account{Username: "orders_app"}, "Some-Password-123")
	if err == nil {
		t.Fatal("wrong master password accepted")
	}
	if strings.Contains(err.Error(), "wrong-master-pw") {
		t.Fatalf("error leaks password: %v", err)
	}

	if err := e.SetPassword(ctx, endpoint, master, engine.Account{Username: "orders_app"}, "şifre-with-unicode"); err == nil {
		t.Fatal("non-ASCII password accepted")
	}
}

func TestPasswordNotLogged(t *testing.T) {
	ctx := t.Context()
	createRole(t, "log_check", "initial-password")
	const secret = "Very-Secret-Rotated-Password-42"
	if err := (Engine{}).SetPassword(ctx, endpoint, master, engine.Account{Username: "log_check"}, secret); err != nil {
		t.Fatal(err)
	}

	r, err := container.Logs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	logs, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logs), `ALTER ROLE "log_check"`) {
		t.Fatal("statement logging is not active; the check below would be meaningless")
	}
	if strings.Contains(string(logs), secret) {
		t.Fatal("server log contains the plain password")
	}
}
