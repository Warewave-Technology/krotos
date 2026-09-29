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

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

const (
	every30d    = "30d"
	saturday3am = "0 3 * * 6"
)

func TestNewScheduleRejectsInvalidSpecs(t *testing.T) {
	cases := map[string]krotosv1alpha1.Schedule{
		"neither":          {},
		"both":             {Cron: saturday3am, Every: every30d},
		"bad cron":         {Cron: "not a cron"},
		"six field cron":   {Cron: "0 0 3 * * 6"},
		"cron with TZ":     {Cron: "TZ=UTC 0 3 * * 6"},
		"cron with CRONTZ": {Cron: "CRON_TZ=UTC 0 3 * * 6"},
		"every no unit":    {Every: "30"},
		"every minutes":    {Every: "30m"},
		"every zero":       {Every: "0d"},
		"every negative":   {Every: "-1d"},
		"every only unit":  {Every: "d"},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSchedule(spec, time.UTC); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestIntervalSchedule(t *testing.T) {
	ref := at(time.UTC, 10, 3, 2, 15)
	cases := []struct {
		every   string
		rotated bool
		want    time.Time
	}{
		{"30d", false, ref},
		{"30d", true, ref.Add(30 * 24 * time.Hour)},
		{"12h", true, ref.Add(12 * time.Hour)},
		{"1d", true, ref.Add(24 * time.Hour)},
	}
	for _, tc := range cases {
		s, err := NewSchedule(krotosv1alpha1.Schedule{Every: tc.every}, time.UTC)
		if err != nil {
			t.Fatalf("NewSchedule(%q): %v", tc.every, err)
		}
		if got := s.NextDue(ref, tc.rotated); !got.Equal(tc.want) {
			t.Errorf("every %s rotated=%v: NextDue = %v, want %v", tc.every, tc.rotated, got, tc.want)
		}
	}
}

func TestCronScheduleUsesWindowTimezone(t *testing.T) {
	s, err := NewSchedule(krotosv1alpha1.Schedule{Cron: saturday3am}, istanbul)
	if err != nil {
		t.Fatal(err)
	}
	// Reference given in UTC must still yield Saturday 03:00 Istanbul time.
	got := s.NextDue(at(time.UTC, 9, 29, 12, 0), false)
	if want := at(istanbul, 10, 3, 3, 0); !got.Equal(want) {
		t.Fatalf("NextDue = %v, want %v", got, want)
	}
	// The tick after a rotation at that instant is the following Saturday.
	got = s.NextDue(at(istanbul, 10, 3, 3, 0), true)
	if want := at(istanbul, 10, 10, 3, 0); !got.Equal(want) {
		t.Fatalf("NextDue = %v, want %v", got, want)
	}
}

func TestCronScheduleDescriptor(t *testing.T) {
	s, err := NewSchedule(krotosv1alpha1.Schedule{Cron: "@monthly"}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.NextDue(at(time.UTC, 9, 29, 12, 0), true), at(time.UTC, 10, 1, 0, 0); !got.Equal(want) {
		t.Fatalf("NextDue = %v, want %v", got, want)
	}
}
