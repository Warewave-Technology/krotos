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

// Package postgres implements engine.Engine for PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/warewave/krotos/internal/engine"
)

// Engine is the PostgreSQL engine.
type Engine struct{}

var _ engine.Engine = Engine{}

// SetPassword implements engine.Engine. The password is sent as a SCRAM-SHA-256
// verifier so it never appears in plain text in server logs.
func (Engine) SetPassword(ctx context.Context, ep engine.Endpoint, master engine.Credentials, account engine.Account, password string) error {
	if !isSCRAMSafe(password) {
		// Only possible when rolling back to a pre-existing password we did not generate.
		return errors.New("password contains characters outside printable ASCII; rotate it manually first")
	}
	verifier, err := scramVerifier(password)
	if err != nil {
		return err
	}

	conn, err := connect(ctx, ep, master)
	if err != nil {
		return err
	}
	defer closeConn(conn)

	// ALTER ROLE does not accept bind parameters. The identifier is quoted by pgx and
	// the verifier only contains base64 characters, '$' and ':'.
	stmt := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s",
		pgx.Identifier{account.Username}.Sanitize(), quoteLiteral(verifier))
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("alter role %q: %w", account.Username, redact(err))
	}
	return nil
}

// VerifyLogin implements engine.Engine.
func (Engine) VerifyLogin(ctx context.Context, ep engine.Endpoint, creds engine.Credentials) error {
	conn, err := connect(ctx, ep, creds)
	if err != nil {
		return err
	}
	defer closeConn(conn)

	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("query as %q: %w", creds.Username, redact(err))
	}
	return nil
}

func connect(ctx context.Context, ep engine.Endpoint, creds engine.Credentials) (*pgx.Conn, error) {
	tlsCfg, err := engine.TLSConfig(ep)
	if err != nil {
		return nil, err
	}

	// Every connection setting is overridden below, so PG* environment variables
	// and .pgpass in the operator's environment have no effect.
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host = ep.Host
	cfg.Port = uint16(ep.Port)
	cfg.Database = ep.Database
	cfg.User = creds.Username
	cfg.Password = creds.Password
	cfg.TLSConfig = tlsCfg
	cfg.Fallbacks = nil
	cfg.ConnectTimeout = engine.ConnectTimeout
	cfg.RuntimeParams = map[string]string{"application_name": "krotos"}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to %s:%d as %q: %w", ep.Host, ep.Port, creds.Username, redact(err))
	}
	return conn, nil
}

func closeConn(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), engine.ConnectTimeout)
	defer cancel()
	_ = conn.Close(ctx)
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// redact reduces server errors to their message and code; pgconn errors never
// contain the password, but connection errors can embed the full config.
func redact(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return fmt.Errorf("%s (SQLSTATE %s)", pgErr.Message, pgErr.Code)
	}
	if connErr, ok := errors.AsType[*pgconn.ConnectError](err); ok {
		return errors.New(connErr.Error())
	}
	return err
}
