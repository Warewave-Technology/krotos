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

// Package clickhouse implements engine.Engine for ClickHouse. Only users managed
// by SQL-driven access control can be rotated; users defined in users.xml cannot
// be changed with ALTER USER.
package clickhouse

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	ch "github.com/ClickHouse/clickhouse-go/v2"

	"github.com/warewave/krotos/internal/engine"
)

// Engine is the ClickHouse engine.
type Engine struct{}

var _ engine.Engine = Engine{}

// SetPassword implements engine.Engine. The password is sent as a salted
// SHA-256 hash, so it never appears in plain text in query_log or server logs.
func (Engine) SetPassword(ctx context.Context, ep engine.Endpoint, master engine.Credentials, account engine.Account, password string) error {
	stmt, err := alterUserStatement(account.Username, ep.ClickHouseCluster, password)
	if err != nil {
		return err
	}
	conn, err := connect(ep, master)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("alter user %q: %w", account.Username, redact(err))
	}
	return nil
}

// VerifyLogin implements engine.Engine.
func (Engine) VerifyLogin(ctx context.Context, ep engine.Endpoint, creds engine.Credentials) error {
	conn, err := connect(ep, creds)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	var one uint8
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("login as %q: %w", creds.Username, redact(err))
	}
	return nil
}

// alterUserStatement builds ALTER USER with a sha256_hash, which replaces all of
// the user's existing authentication methods.
func alterUserStatement(user, cluster, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	saltHex := hex.EncodeToString(salt)
	sum := sha256.Sum256([]byte(password + saltHex))

	var b strings.Builder
	b.WriteString("ALTER USER ")
	b.WriteString(quoteIdentifier(user))
	if cluster != "" {
		b.WriteString(" ON CLUSTER ")
		b.WriteString(quoteIdentifier(cluster))
	}
	// Hash and salt are hex, so they need no escaping.
	fmt.Fprintf(&b, " IDENTIFIED WITH sha256_hash BY '%s' SALT '%s'", hex.EncodeToString(sum[:]), saltHex)
	return b.String(), nil
}

// quoteIdentifier quotes a ClickHouse identifier with backticks.
func quoteIdentifier(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "`", "\\`")
	return "`" + s + "`"
}

func connect(ep engine.Endpoint, creds engine.Credentials) (ch.Conn, error) {
	tlsCfg, err := engine.TLSConfig(ep)
	if err != nil {
		return nil, err
	}
	protocol := ch.Native
	if ep.ClickHouseProtocol == "http" {
		protocol = ch.HTTP
	}
	database := ep.Database
	if database == "" {
		database = "default"
	}
	conn, err := ch.Open(&ch.Options{
		Protocol: protocol,
		Addr:     []string{net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))},
		Auth: ch.Auth{
			Database: database,
			Username: creds.Username,
			Password: creds.Password,
		},
		TLS:          tlsCfg,
		DialTimeout:  engine.ConnectTimeout,
		ReadTimeout:  engine.ConnectTimeout,
		MaxOpenConns: 1,
		ClientInfo:   ch.ClientInfo{Products: []struct{ Name, Version string }{{Name: "krotos", Version: "1"}}},
	})
	if err != nil {
		return nil, fmt.Errorf("connect to %s:%d as %q: %w", ep.Host, ep.Port, creds.Username, redact(err))
	}
	return conn, nil
}

// redact keeps server errors to their code and message.
func redact(err error) error {
	if ex, ok := errors.AsType[*ch.Exception](err); ok {
		return fmt.Errorf("%s (code %d)", ex.Message, ex.Code)
	}
	return err
}
