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
	"slices"
	"testing"

	"github.com/Warewave-Technology/krotos/internal/engine"
)

func TestPasswordHash(t *testing.T) {
	// echo -n password | sha256sum
	if got, want := passwordHash("password"), "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; got != want {
		t.Fatalf("passwordHash = %s, want %s", got, want)
	}
}

func TestAddrs(t *testing.T) {
	ep := engine.Endpoint{Host: "redis-0.redis", Port: 6379, RedisNodes: []string{"redis-1.redis:6379", "redis-0.redis:6379"}}
	if got, want := addrs(ep), []string{"redis-0.redis:6379", "redis-1.redis:6379"}; !slices.Equal(got, want) {
		t.Fatalf("addrs = %v, want %v", got, want)
	}
}
