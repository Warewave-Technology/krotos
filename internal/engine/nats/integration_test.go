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

package nats

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

const templatePath = "../../../docs/least-privilege/nats.sh"

var images = []string{"nats:2.10-alpine", "nats:2.11-alpine", "nats:2.12-alpine"}

// setup is an operator-mode server with a full (NATS-based) resolver, and the
// account ORDERS prepared with the least-privilege template.
type setup struct {
	ep      engine.Endpoint
	seed    string // the scoped signing key from the template
	creds   string // orders-service's credentials from the template
	account string // ORDERS' public key
}

func newSetup(t *testing.T, image string) *setup {
	t.Helper()
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nw.Remove(ctx) })

	box := start(t, testcontainers.ContainerRequest{
		Image:      "natsio/nats-box:0.20.0",
		Cmd:        []string{"sleep", "infinity"},
		Env:        map[string]string{"NKEYS_PATH": "/w/keys", "NSC_HOME": "/w/nsc"},
		Networks:   []string{nw.Name},
		WaitingFor: wait.ForExec([]string{"true"}),
	})
	run(t, box, `mkdir -p /w/store && cd /w && nsc env -s /w/store >/dev/null &&
nsc add operator --generate-signing-key --sys --name test &&
nsc edit operator --account-jwt-server-url nats://nats:4222 &&
nsc add account ORDERS &&
nsc generate config --nats-resolver --sys-account SYS --config-file /w/server.conf &&
sed -i 's|dir: .*|dir: "/tmp/jwt"|' /w/server.conf`)
	conf := read(t, box, "/w/server.conf")

	srv := start(t, testcontainers.ContainerRequest{
		Image:          image,
		Cmd:            []string{"-c", "/etc/nats/server.conf"},
		ExposedPorts:   []string{"4222/tcp"},
		Networks:       []string{nw.Name},
		NetworkAliases: map[string][]string{nw.Name: {"nats"}},
		Files: []testcontainers.ContainerFile{{
			Reader: strings.NewReader(conf), ContainerFilePath: "/etc/nats/server.conf", FileMode: 0o644,
		}},
		WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(time.Minute),
	})

	tpl, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := box.CopyToContainer(ctx, tpl, "/w/nats.sh", 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, box, "cd /w && sh -e nats.sh")

	host, err := srv.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := srv.MappedPort(ctx, "4222/tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := &setup{
		ep: engine.Endpoint{
			Host: host, Port: int32(port.Num()), TLSMode: "disable", NATSCredentialsTTL: time.Hour,
		},
		seed:    strings.TrimSpace(read(t, box, "/w/krotos-orders.seed")),
		creds:   read(t, box, "/w/orders-service.creds"),
		account: strings.TrimSpace(run(t, box, "nsc describe account ORDERS --field sub | tr -d '\"'")),
	}
	return s
}

func start(t *testing.T, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	c, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("start %s: %v", req.Image, err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	return c
}

func run(t *testing.T, c testcontainers.Container, script string) string {
	t.Helper()
	code, out, err := c.Exec(context.Background(), []string{"sh", "-c", script}, tcexec.Multiplexed())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(out)
	if code != 0 {
		t.Fatalf("%s: exit %d\n%s", script, code, b)
	}
	return string(b)
}

func read(t *testing.T, c testcontainers.Container, path string) string {
	t.Helper()
	r, err := c.CopyFileFromContainer(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (s *setup) connect(t *testing.T, creds string, opts ...natsgo.Option) (*natsgo.Conn, error) {
	t.Helper()
	token, seed, err := parseCreds(creds)
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, natsgo.UserJWTAndSeed(token, seed), natsgo.NoReconnect())
	return natsgo.Connect("nats://"+net.JoinHostPort(s.ep.Host, strconv.Itoa(int(s.ep.Port))), opts...)
}

func rotate(t *testing.T, s *setup, current string) string {
	t.Helper()
	e := Engine{}
	master := engine.Credentials{Password: s.seed}
	if err := e.Preflight(t.Context(), s.ep, master); err != nil {
		t.Fatal(err)
	}
	next, err := e.Issue(t.Context(), s.ep, master, engine.Account{Username: "orders-service"}, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.VerifyLogin(t.Context(), s.ep, engine.Credentials{Password: next}); err != nil {
		t.Fatalf("new credentials do not work: %v", err)
	}
	return next
}

func TestRotationWithTemplate(t *testing.T) {
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			s := newSetup(t, image)
			e := Engine{}
			if err := e.VerifyLogin(t.Context(), s.ep, engine.Credentials{Password: s.creds}); err != nil {
				t.Fatalf("template credentials do not work: %v", err)
			}

			next := rotate(t, s, s.creds)
			// And once more, from the issued credentials.
			next = rotate(t, s, next)
			if decode(t, next).Subject == decode(t, s.creds).Subject {
				t.Fatal("same user key after rotation")
			}

			// The scope, not krotos, decides what the user may do.
			permErr := make(chan error, 1)
			nc, err := s.connect(t, next, natsgo.ErrorHandler(func(_ *natsgo.Conn, _ *natsgo.Subscription, err error) {
				select {
				case permErr <- err:
				default:
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			if err := nc.Publish("orders.created", []byte("ok")); err != nil {
				t.Fatal(err)
			}
			if err := nc.Publish("admin.shutdown", []byte("no")); err != nil {
				t.Fatal(err)
			}
			_ = nc.Flush()
			select {
			case err := <-permErr:
				if !errors.Is(err, natsgo.ErrPermissionViolation) && !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
					t.Fatalf("unexpected async error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("publishing outside the scope was not refused")
			}
		})
	}
}

// Expiry is what retires old credentials: the server must refuse them, and drop
// connections made with them, once they expire.
func TestServerEnforcesExpiry(t *testing.T) {
	s := newSetup(t, images[len(images)-1])
	s.ep.NATSCredentialsTTL = 3 * time.Second
	short := rotate(t, s, s.creds)

	closed := make(chan struct{})
	nc, err := s.connect(t, short, natsgo.ClosedHandler(func(*natsgo.Conn) { close(closed) }))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	select {
	case <-closed:
	case <-time.After(15 * time.Second):
		t.Fatal("the server kept a connection with expired credentials")
	}

	// Expiry has one-second resolution and the server refuses from the next second on.
	time.Sleep(time.Until(time.Unix(decode(t, short).Expires+1, 0)))
	if _, err := s.connect(t, short); err == nil {
		t.Fatal("the server accepted expired credentials")
	}
	err = Engine{}.VerifyLogin(t.Context(), s.ep, engine.Credentials{Password: short})
	if !errors.Is(err, engine.ErrCredentialsExpired) {
		t.Fatalf("VerifyLogin = %v, want ErrCredentialsExpired", err)
	}
	// Expired credentials are replaced like any others.
	rotate(t, s, short)
}

// Users signed by a scoped key must carry no permissions of their own; the server
// refuses them otherwise. Such credentials fail verification, and the rotation
// rolls back without changing anything.
func TestScopedKeyRefusesUserPermissions(t *testing.T) {
	s := newSetup(t, images[len(images)-1])
	signer, err := nkeys.FromSeed([]byte(s.seed))
	if err != nil {
		t.Fatal(err)
	}
	withPerms := userCreds(t, signer, s.account, time.Now().Add(time.Hour), func(uc *jwt.UserClaims) {
		uc.Pub.Allow.Add("admin.>")
	})
	if err := (Engine{}).VerifyLogin(t.Context(), s.ep, engine.Credentials{Password: withPerms}); err == nil {
		t.Fatal("the server accepted a scoped user with its own permissions")
	}
}

func TestWrongAccountKeyFailsVerification(t *testing.T) {
	s := newSetup(t, images[len(images)-1])
	_, _, otherSeed := mustKey(t, nkeys.CreateAccount)
	next, err := Engine{}.Issue(t.Context(), s.ep, engine.Credentials{Password: otherSeed},
		engine.Account{Username: "orders-service"}, s.creds)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Engine{}).VerifyLogin(t.Context(), s.ep, engine.Credentials{Password: next}); err == nil {
		t.Fatal("credentials signed by a key the account does not know were accepted")
	}
}
