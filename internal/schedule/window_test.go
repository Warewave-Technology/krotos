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

package schedule

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

var (
	istanbul = mustLoad("Europe/Istanbul")
	berlin   = mustLoad("Europe/Berlin")
)

func mustLoad(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

// at builds a time in loc. 2026-10-03 is a Saturday.
func at(loc *time.Location, month time.Month, day, hour, minute int) time.Time {
	return time.Date(2026, month, day, hour, minute, 0, 0, loc)
}

func windowSpec(tz, start string, d time.Duration, days ...krotosv1alpha1.Weekday) krotosv1alpha1.MaintenanceWindow {
	return krotosv1alpha1.MaintenanceWindow{
		Timezone: tz,
		Days:     days,
		Start:    start,
		Duration: metav1.Duration{Duration: d},
	}
}

func mustWindow(t *testing.T, spec krotosv1alpha1.MaintenanceWindow) *Window {
	t.Helper()
	w, err := NewWindow(spec)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	return w
}

func TestNewWindowRejectsInvalidSpecs(t *testing.T) {
	cases := map[string]krotosv1alpha1.MaintenanceWindow{
		"unknown timezone": windowSpec("Mars/Olympus", "02:00", time.Hour),
		"bad start":        windowSpec("UTC", "2am", time.Hour),
		"zero duration":    windowSpec("UTC", "02:00", 0),
		"too long":         windowSpec("UTC", "02:00", 25*time.Hour),
		"unknown day":      windowSpec("UTC", "02:00", time.Hour, "Funday"),
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewWindow(spec); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNewWindowDefaultsToUTC(t *testing.T) {
	w := mustWindow(t, windowSpec("", "02:00", time.Hour))
	if w.Location() != time.UTC {
		t.Fatalf("location = %v, want UTC", w.Location())
	}
}

func TestWindowContains(t *testing.T) {
	weekend := mustWindow(t, windowSpec("Europe/Istanbul", "02:00", 3*time.Hour, "Sat", "Sun"))
	overnight := mustWindow(t, windowSpec("Europe/Istanbul", "23:00", 3*time.Hour, "Sat"))
	daily := mustWindow(t, windowSpec("UTC", "00:00", 24*time.Hour))

	cases := []struct {
		name    string
		w       *Window
		t       time.Time
		want    bool
		wantEnd time.Time
	}{
		{"at opening", weekend, at(istanbul, 10, 3, 2, 0), true, at(istanbul, 10, 3, 5, 0)},
		{"inside", weekend, at(istanbul, 10, 4, 3, 30), true, at(istanbul, 10, 4, 5, 0)},
		{"at closing is outside", weekend, at(istanbul, 10, 3, 5, 0), false, time.Time{}},
		{"before opening", weekend, at(istanbul, 10, 3, 1, 59), false, time.Time{}},
		{"weekday", weekend, at(istanbul, 10, 2, 3, 0), false, time.Time{}},
		{"same instant in another zone", weekend, at(time.UTC, 10, 3, 0, 30), true, at(istanbul, 10, 3, 5, 0)},
		{"overnight before midnight", overnight, at(istanbul, 10, 3, 23, 30), true, at(istanbul, 10, 4, 2, 0)},
		{"overnight after midnight", overnight, at(istanbul, 10, 4, 1, 30), true, at(istanbul, 10, 4, 2, 0)},
		{"overnight on a day it does not open", overnight, at(istanbul, 10, 4, 23, 30), false, time.Time{}},
		{"overnight after close", overnight, at(istanbul, 10, 4, 2, 0), false, time.Time{}},
		{"24h daily window", daily, at(time.UTC, 10, 7, 13, 37), true, at(time.UTC, 10, 8, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, ok := tc.w.Contains(tc.t)
			if ok != tc.want {
				t.Fatalf("Contains(%v) = %v, want %v", tc.t, ok, tc.want)
			}
			if !end.Equal(tc.wantEnd) {
				t.Fatalf("end = %v, want %v", end, tc.wantEnd)
			}
		})
	}
}

func TestWindowNextOpen(t *testing.T) {
	weekend := mustWindow(t, windowSpec("Europe/Istanbul", "02:00", 3*time.Hour, "Sat", "Sun"))
	saturday := mustWindow(t, windowSpec("Europe/Istanbul", "02:00", 3*time.Hour, "Sat"))
	daily := mustWindow(t, windowSpec("UTC", "22:00", 2*time.Hour))

	cases := []struct {
		name string
		w    *Window
		t    time.Time
		want time.Time
	}{
		{"inside returns t", weekend, at(istanbul, 10, 3, 3, 0), at(istanbul, 10, 3, 3, 0)},
		{"weekday to saturday", weekend, at(istanbul, 9, 29, 12, 0), at(istanbul, 10, 3, 2, 0)},
		{"after saturday window to sunday", weekend, at(istanbul, 10, 3, 6, 0), at(istanbul, 10, 4, 2, 0)},
		{"after sunday window to next saturday", weekend, at(istanbul, 10, 4, 6, 0), at(istanbul, 10, 10, 2, 0)},
		{"single day, just missed", saturday, at(istanbul, 10, 3, 5, 0), at(istanbul, 10, 10, 2, 0)},
		{"single day, earlier same day", saturday, at(istanbul, 10, 3, 1, 0), at(istanbul, 10, 3, 2, 0)},
		{"daily later today", daily, at(time.UTC, 10, 7, 10, 0), at(time.UTC, 10, 7, 22, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.NextOpen(tc.t); !got.Equal(tc.want) {
				t.Fatalf("NextOpen(%v) = %v, want %v", tc.t, got, tc.want)
			}
		})
	}
}

func TestWindowAcrossDST(t *testing.T) {
	// Berlin springs forward on 2026-03-29 at 02:00 -> 03:00; 02:30 does not exist.
	gap := mustWindow(t, windowSpec("Europe/Berlin", "02:30", time.Hour, "Sun"))
	got := gap.NextOpen(at(berlin, 3, 28, 12, 0))
	if want := at(berlin, 3, 29, 3, 30); !got.Equal(want) {
		t.Fatalf("NextOpen across spring-forward gap = %v, want %v", got, want)
	}

	// Berlin falls back on 2026-10-25; a window at 04:00 is 25h after the previous day's.
	fallback := mustWindow(t, windowSpec("Europe/Berlin", "04:00", time.Hour))
	got = fallback.NextOpen(at(berlin, 10, 24, 5, 0))
	if want := at(berlin, 10, 25, 4, 0); !got.Equal(want) {
		t.Fatalf("NextOpen across fall-back = %v, want %v", got, want)
	}
	if d := got.Sub(at(berlin, 10, 24, 4, 0)); d != 25*time.Hour {
		t.Fatalf("distance between openings = %v, want 25h", d)
	}
}

func TestWindowMinRemaining(t *testing.T) {
	spec := windowSpec("Europe/Istanbul", "02:00", 3*time.Hour, "Sat", "Sun")
	spec.MinRemaining = metav1.Duration{Duration: 15 * time.Minute}
	w := mustWindow(t, spec)

	cases := []struct {
		name      string
		t         time.Time
		canStart  bool
		nextStart time.Time
	}{
		{"plenty left", at(istanbul, 10, 3, 3, 0), true, at(istanbul, 10, 3, 3, 0)},
		{"exactly minRemaining left", at(istanbul, 10, 3, 4, 45), true, at(istanbul, 10, 3, 4, 45)},
		{"too little left", at(istanbul, 10, 3, 4, 50), false, at(istanbul, 10, 4, 2, 0)},
		{"too little left on last day", at(istanbul, 10, 4, 4, 50), false, at(istanbul, 10, 10, 2, 0)},
		{"outside", at(istanbul, 9, 29, 12, 0), false, at(istanbul, 10, 3, 2, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := w.CanStart(tc.t); got != tc.canStart {
				t.Fatalf("CanStart(%v) = %v, want %v", tc.t, got, tc.canStart)
			}
			if got := w.NextStart(tc.t); !got.Equal(tc.nextStart) {
				t.Fatalf("NextStart(%v) = %v, want %v", tc.t, got, tc.nextStart)
			}
		})
	}
}

func TestWindowMinRemainingWithBackToBackWindows(t *testing.T) {
	// A 24h daily window never closes; the tail of one day flows into the next day's window.
	spec := windowSpec("UTC", "00:00", 24*time.Hour)
	spec.MinRemaining = metav1.Duration{Duration: time.Hour}
	w := mustWindow(t, spec)

	tail := at(time.UTC, 10, 7, 23, 30)
	if w.CanStart(tail) {
		t.Fatal("CanStart in the last 30m of a 24h window with minRemaining 1h")
	}
	if got, want := w.NextStart(tail), at(time.UTC, 10, 8, 0, 0); !got.Equal(want) {
		t.Fatalf("NextStart = %v, want %v", got, want)
	}
}

func TestNewWindowRejectsInvalidMinRemaining(t *testing.T) {
	for _, d := range []time.Duration{-time.Minute, time.Hour, 2 * time.Hour} {
		spec := windowSpec("UTC", "02:00", time.Hour)
		spec.MinRemaining = metav1.Duration{Duration: d}
		if _, err := NewWindow(spec); err == nil {
			t.Errorf("minRemaining %v: expected an error", d)
		}
	}
}
