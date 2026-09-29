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

import "testing"

func TestNativePasswordHash(t *testing.T) {
	// The well-known value of MySQL's PASSWORD('password').
	if got, want := nativePasswordHash("password"), "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"; got != want {
		t.Fatalf("nativePasswordHash = %s, want %s", got, want)
	}
}
