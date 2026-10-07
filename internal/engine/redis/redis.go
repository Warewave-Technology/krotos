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

// Package redis implements engine.Engine for Redis 6+ and Valkey ACL users.
//
// ACL changes live in memory and are not replicated, so the password is changed
// on every listed node and then persisted on each (ACL SAVE, or CONFIG REWRITE when
// asked for); otherwise a restarted server would come back with the old password.
package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

// Persistence modes, as in the API.
const (
	persistAuto          = "Auto"
	persistACLFile       = "ACLFile"
	persistConfigRewrite = "ConfigRewrite"
	persistNone          = "None"
)

// Engine is the Redis / Valkey engine.
type Engine struct{}

var (
	_ engine.Engine      = Engine{}
	_ engine.Preflighter = Engine{}
)

// Preflight implements engine.Preflighter: every node must be reachable with the
// master credentials and able to persist the change the way the spec asks.
func (Engine) Preflight(ctx context.Context, ep engine.Endpoint, master engine.Credentials) error {
	for _, addr := range addrs(ep) {
		err := withClient(ctx, ep, addr, master, func(c *goredis.Client) error {
			_, err := persistMethod(ctx, c, ep.RedisPersistence)
			return err
		})
		if err != nil {
			return fmt.Errorf("%s: %w", addr, err)
		}
	}
	return nil
}

// SetPassword implements engine.Engine. Only the user's passwords change; its other
// ACL rules are kept. The password is sent as its SHA-256 hash, so it never shows
// up in MONITOR output or the ACL file.
func (Engine) SetPassword(ctx context.Context, ep engine.Endpoint, master engine.Credentials, account engine.Account, password string) error {
	for _, addr := range addrs(ep) {
		err := withClient(ctx, ep, addr, master, func(c *goredis.Client) error {
			if err := c.Do(ctx, "ACL", "SETUSER", account.Username, "resetpass", "#"+passwordHash(password)).Err(); err != nil {
				return fmt.Errorf("acl setuser %q: %w", account.Username, err)
			}
			method, err := persistMethod(ctx, c, ep.RedisPersistence)
			if err != nil {
				return err
			}
			return persist(ctx, c, method)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", addr, err)
		}
	}
	return nil
}

// VerifyLogin implements engine.Engine; it logs in on every node, since
// applications may connect to any of them. Only AUTH is sent: every user may run
// it, while the application user may not be allowed even PING.
func (Engine) VerifyLogin(ctx context.Context, ep engine.Endpoint, creds engine.Credentials) error {
	for _, addr := range addrs(ep) {
		c, err := newClient(ep, addr, engine.Credentials{})
		if err != nil {
			return err
		}
		err = c.Do(ctx, "AUTH", creds.Username, creds.Password).Err()
		_ = c.Close()
		if err != nil {
			return fmt.Errorf("%s: login as %q: %w", addr, creds.Username, err)
		}
	}
	return nil
}

// persistMethod resolves the persistence mode to the command to run, checking that
// the server supports it.
func persistMethod(ctx context.Context, c *goredis.Client, mode string) (string, error) {
	switch mode {
	case persistNone:
		return persistNone, nil
	case persistACLFile:
		if aclFile, err := configValue(ctx, c, "aclfile"); err != nil || aclFile == "" {
			return "", errors.Join(errors.New("persistence ACLFile needs the aclfile directive"), err)
		}
		return persistACLFile, nil
	case persistConfigRewrite:
		if file, err := configFile(ctx, c); err != nil || file == "" {
			return "", errors.Join(errors.New("persistence ConfigRewrite needs a server started with a config file"), err)
		}
		return persistConfigRewrite, nil
	case persistAuto, "":
		// Only ACL SAVE is chosen automatically: it writes nothing but the users.
		// CONFIG REWRITE rewrites the whole config file, including runtime CONFIG SET
		// changes and command-line arguments (with the official Redis 8 image it writes
		// the bundled modules into the file, and the server no longer starts).
		aclFile, err := configValue(ctx, c, "aclfile")
		if err != nil {
			return "", err
		}
		if aclFile != "" {
			return persistACLFile, nil
		}
		return "", errors.New("the server has no aclfile, so a changed password would be lost on restart; " +
			"use an aclfile, or set database.redis.persistence to ConfigRewrite (rewrites the whole " +
			"config file) or None (the old password returns after a restart)")
	default:
		return "", fmt.Errorf("unknown persistence %q", mode)
	}
}

func persist(ctx context.Context, c *goredis.Client, method string) error {
	switch method {
	case persistACLFile:
		if err := c.Do(ctx, "ACL", "SAVE").Err(); err != nil {
			return fmt.Errorf("acl save: %w", err)
		}
	case persistConfigRewrite:
		if err := c.ConfigRewrite(ctx).Err(); err != nil {
			return fmt.Errorf("config rewrite: %w", err)
		}
	}
	return nil
}

func configValue(ctx context.Context, c *goredis.Client, key string) (string, error) {
	values, err := c.ConfigGet(ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("config get %s: %w", key, err)
	}
	return values[key], nil
}

// configFile is the path of the server's config file, empty when it has none.
func configFile(ctx context.Context, c *goredis.Client) (string, error) {
	info, err := c.Info(ctx, "server").Result()
	if err != nil {
		return "", fmt.Errorf("info server: %w", err)
	}
	for line := range strings.SplitSeq(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "config_file:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}

// passwordHash is the form Redis stores and accepts with the "#" ACL rule.
func passwordHash(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// addrs is database.host:port followed by the extra nodes.
func addrs(ep engine.Endpoint) []string {
	out := []string{net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))}
	for _, n := range ep.RedisNodes {
		if n != out[0] {
			out = append(out, n)
		}
	}
	return out
}

// withClient connects to addr as creds (AUTH + PING) and runs fn.
func withClient(ctx context.Context, ep engine.Endpoint, addr string, creds engine.Credentials, fn func(*goredis.Client) error) error {
	c, err := newClient(ep, addr, creds)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.Ping(ctx).Err(); err != nil {
		return err
	}
	return fn(c)
}

// newClient returns a client for addr; with empty creds it does not authenticate.
func newClient(ep engine.Endpoint, addr string, creds engine.Credentials) (*goredis.Client, error) {
	tlsCfg, err := engine.TLSConfig(ep)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		// Each node is verified against its own host name.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
	}
	return goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Username: creds.Username,
		Password: creds.Password,
		// RESP2 authenticates with AUTH, which every user may run; RESP3 would send
		// HELLO, which a least-privilege user may not be allowed to.
		Protocol:        2,
		DisableIdentity: true,
		TLSConfig:       tlsCfg,
		DialTimeout:     engine.ConnectTimeout,
		ReadTimeout:     engine.ConnectTimeout,
		WriteTimeout:    engine.ConnectTimeout,
		PoolSize:        1,
		MaxRetries:      -1,
	}), nil
}
