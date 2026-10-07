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

package redis

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

const (
	appUser      = "orders_app"
	appOld       = "old-app-password"
	appNew       = "Very-Secret-Rotated-Password-42"
	rotatorUser  = "krotos_rotator"
	rotatorPass  = "rotator-password"
	templatePath = "../../../docs/least-privilege/redis.acl"
	adminACL     = "user default on nopass ~* &* +@all\n"
)

var rotator = engine.Credentials{Username: rotatorUser, Password: rotatorPass}

type flavor struct {
	name, image, server string
}

var flavors = []flavor{
	{"redis-7.4", "redis:7.4-alpine", "redis-server"},
	{"redis-8.2", "redis:8.2-alpine", "redis-server"},
	{"valkey-8", "valkey/valkey:8-alpine", "valkey-server"},
}

type serverOpts struct {
	args    []string
	files   map[string]string
	network *testcontainers.DockerNetwork
	aliases []string
}

func start(t *testing.T, f flavor, o serverOpts) testcontainers.Container {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        f.image,
		Cmd:          append([]string{f.server}, o.args...),
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(time.Minute),
	}
	for path, content := range o.files {
		req.Files = append(req.Files, testcontainers.ContainerFile{
			Reader: strings.NewReader(content), ContainerFilePath: path, FileMode: 0o666,
		})
	}
	if o.network != nil {
		req.Networks = []string{o.network.Name}
		req.NetworkAliases = map[string][]string{o.network.Name: o.aliases}
	}
	c, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("start %s: %v", f.image, err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	return c
}

func addrOf(t *testing.T, c testcontainers.Container) (string, int32) {
	t.Helper()
	ctx := context.Background()
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return host, int32(port.Num())
}

func endpointOf(t *testing.T, c testcontainers.Container, persistence string) engine.Endpoint {
	t.Helper()
	host, port := addrOf(t, c)
	return engine.Endpoint{Host: host, Port: port, RedisPersistence: persistence}
}

func client(ep engine.Endpoint, user, pass string) *goredis.Client {
	return goredis.NewClient(&goredis.Options{
		Addr:     ep.Host + ":" + strconv.Itoa(int(ep.Port)),
		Username: user, Password: pass, Protocol: 2, DisableIdentity: true,
	})
}

// setupUsers creates the application user and the rotator from the README template.
func setupUsers(t *testing.T, ep engine.Endpoint, persistCmd ...string) {
	t.Helper()
	ctx := t.Context()
	admin := client(ep, "", "")
	defer func() { _ = admin.Close() }()
	must(t, admin.Do(ctx, "ACL", "SETUSER", appUser, "on", ">"+appOld, "~app:*", "+@read").Err())

	runTemplate(t, ep, templatePath)
	if len(persistCmd) > 0 {
		args := make([]any, 0, len(persistCmd))
		for _, a := range persistCmd {
			args = append(args, a)
		}
		must(t, admin.Do(ctx, args...).Err())
	}
}

// runTemplate runs a least-privilege template from docs/ as the admin user.
func runTemplate(t *testing.T, ep engine.Endpoint, path string) {
	t.Helper()
	admin := client(ep, "", "")
	defer func() { _ = admin.Close() }()
	tpl, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(tpl), "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "change-me", rotatorPass))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		args := []any{}
		for f := range strings.FieldsSeq(line) {
			args = append(args, f)
		}
		must(t, admin.Do(t.Context(), args...).Err())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func loginWorks(t *testing.T, ep engine.Endpoint, pass string) bool {
	t.Helper()
	return Engine{}.VerifyLogin(t.Context(), ep, engine.Credentials{Username: appUser, Password: pass}) == nil
}

func rotate(t *testing.T, ep engine.Endpoint) {
	t.Helper()
	e := Engine{}
	must(t, e.Preflight(t.Context(), ep, rotator))
	must(t, e.SetPassword(t.Context(), ep, rotator, engine.Account{Username: appUser}, appNew))
}

func restart(t *testing.T, c testcontainers.Container) {
	t.Helper()
	ctx := context.Background()
	timeout := 10 * time.Second
	must(t, c.Stop(ctx, &timeout))
	must(t, c.Start(ctx))
}

func waitReady(t *testing.T, ep engine.Endpoint) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		c := client(ep, "", "")
		err := c.Ping(t.Context()).Err()
		_ = c.Close()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come back: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The change must survive a restart; otherwise the server would come back with the
// old password while Vault holds the new one.
func TestPersistence(t *testing.T) {
	for _, f := range flavors {
		t.Run(f.name+"/aclfile", func(t *testing.T) {
			c := start(t, f, serverOpts{
				args:  []string{"--aclfile", "/data/users.acl"},
				files: map[string]string{"/data/users.acl": adminACL},
			})
			ep := endpointOf(t, c, persistAuto)
			setupUsers(t, ep, "ACL", "SAVE")
			rotate(t, ep)
			if !loginWorks(t, ep, appNew) || loginWorks(t, ep, appOld) {
				t.Fatal("password not rotated")
			}
			restart(t, c)
			ep = endpointOf(t, c, persistAuto)
			waitReady(t, ep)
			if !loginWorks(t, ep, appNew) {
				t.Fatal("new password lost on restart")
			}
			if loginWorks(t, ep, appOld) {
				t.Fatal("old password back after restart")
			}
		})
		t.Run(f.name+"/config-file", func(t *testing.T) {
			if f.name == "redis-8.2" {
				// The official Redis 8 image loads its bundled modules from the command
				// line; CONFIG REWRITE writes them into the file, and the restarted server
				// loads them twice and aborts. That is why Auto never picks CONFIG REWRITE.
				t.Skip("CONFIG REWRITE breaks restarts of the official Redis 8 image")
			}
			c := start(t, f, serverOpts{
				args:  []string{"/data/redis.conf"},
				files: map[string]string{"/data/redis.conf": adminACL + "dir /data\n"},
			})
			ep := endpointOf(t, c, persistAuto)
			setupUsers(t, ep)
			// ConfigRewrite needs the extra template on top of the base one.
			runTemplate(t, ep, "../../../docs/least-privilege/redis-config-rewrite.acl")
			admin := client(ep, "", "")
			must(t, admin.Do(t.Context(), "CONFIG", "REWRITE").Err())
			_ = admin.Close()
			if err := (Engine{}).Preflight(t.Context(), ep, rotator); err == nil || !strings.Contains(err.Error(), "no aclfile") {
				t.Fatalf("Preflight with Auto and only a config file = %v, want a refusal", err)
			}
			ep.RedisPersistence = persistConfigRewrite
			rotate(t, ep)
			restart(t, c)
			ep = endpointOf(t, c, persistConfigRewrite)
			waitReady(t, ep)
			if !loginWorks(t, ep, appNew) || loginWorks(t, ep, appOld) {
				t.Fatal("rotation did not survive a restart")
			}
		})
	}
}

func TestWithoutConfigFile(t *testing.T) {
	c := start(t, flavors[0], serverOpts{})
	ep := endpointOf(t, c, persistAuto)
	setupUsers(t, ep)

	err := Engine{}.Preflight(t.Context(), ep, rotator)
	if err == nil || !strings.Contains(err.Error(), "no aclfile") {
		t.Fatalf("Preflight with Auto = %v, want a refusal", err)
	}
	ep.RedisPersistence = persistACLFile
	if err := (Engine{}).Preflight(t.Context(), ep, rotator); err == nil {
		t.Fatal("Preflight with ACLFile and no aclfile succeeded")
	}

	ep.RedisPersistence = persistNone
	rotate(t, ep)
	if !loginWorks(t, ep, appNew) {
		t.Fatal("password not rotated with persistence None")
	}
}

func TestLeastPrivilegeRotatorCannotReadData(t *testing.T) {
	c := start(t, flavors[0], serverOpts{})
	ep := endpointOf(t, c, persistNone)
	setupUsers(t, ep)
	r := client(ep, rotatorUser, rotatorPass)
	defer func() { _ = r.Close() }()
	if err := r.Get(t.Context(), "app:1").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("rotator GET = %v, want NOPERM", err)
	}
}

// ACL changes are not replicated: every node has to be listed.
func TestReplicaNodes(t *testing.T) {
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nw.Remove(ctx) })
	files := map[string]string{"/data/users.acl": adminACL}

	primary := start(t, flavors[0], serverOpts{
		args: []string{"--aclfile", "/data/users.acl"}, files: files, network: nw, aliases: []string{"primary"},
	})
	replica := start(t, flavors[0], serverOpts{
		args:  []string{"--aclfile", "/data/users.acl", "--replicaof", "primary", "6379"},
		files: files, network: nw, aliases: []string{"replica"},
	})
	pep := endpointOf(t, primary, persistAuto)
	rep := endpointOf(t, replica, persistAuto)

	setupUsers(t, pep, "ACL", "SAVE")
	if loginWorks(t, rep, appOld) {
		t.Fatal("ACL user replicated to the replica; the nodes setting would be unnecessary")
	}
	setupUsers(t, rep, "ACL", "SAVE")

	host, port := addrOf(t, replica)
	pep.RedisNodes = []string{host + ":" + strconv.Itoa(int(port))}
	rotate(t, pep)

	for name, ep := range map[string]engine.Endpoint{"primary": pep, "replica": rep} {
		if !loginWorks(t, ep, appNew) || loginWorks(t, ep, appOld) {
			t.Fatalf("%s: password not rotated", name)
		}
	}
}
