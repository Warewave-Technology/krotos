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

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

func mustPlanner(t *testing.T, sched krotosv1alpha1.Schedule) *Planner {
	t.Helper()
	// Saturday and Sunday 02:00-05:00 Istanbul, starts need 15m left.
	window := windowSpec("Europe/Istanbul", "02:00", 3*time.Hour, "Sat", "Sun")
	window.MinRemaining = metav1.Duration{Duration: 15 * time.Minute}
	p, err := NewPlanner(&krotosv1alpha1.DatabaseCredentialRotationSpec{
		Schedule: sched,
		Window:   window,
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	return p
}

func TestNewPlannerPropagatesErrors(t *testing.T) {
	if _, err := NewPlanner(&krotosv1alpha1.DatabaseCredentialRotationSpec{
		Schedule: krotosv1alpha1.Schedule{Every: every30d},
		Window:   windowSpec("Nowhere/Void", "02:00", time.Hour),
	}); err == nil {
		t.Fatal("expected window error")
	}
	if _, err := NewPlanner(&krotosv1alpha1.DatabaseCredentialRotationSpec{
		Schedule: krotosv1alpha1.Schedule{Cron: "bogus"},
		Window:   windowSpec("UTC", "02:00", time.Hour),
	}); err == nil {
		t.Fatal("expected schedule error")
	}
}

func TestPlannerDecide(t *testing.T) {
	every30 := krotosv1alpha1.Schedule{Every: every30d}
	created := at(istanbul, 8, 1, 12, 0)
	satInside := at(istanbul, 10, 3, 3, 0)
	satWindowEnd := at(istanbul, 10, 3, 5, 0)
	tuesday := at(istanbul, 9, 29, 12, 0)
	nextSat := at(istanbul, 10, 3, 2, 0)

	cases := []struct {
		name          string
		sched         krotosv1alpha1.Schedule
		in            Input
		wantStart     bool
		wantDue       time.Time
		wantNextStart time.Time
		wantWindowEnd time.Time
	}{
		{
			name:          "never rotated, inside window",
			sched:         every30,
			in:            Input{Now: satInside, Created: created},
			wantStart:     true,
			wantDue:       created,
			wantNextStart: satInside,
			wantWindowEnd: satWindowEnd,
		},
		{
			name:          "never rotated, outside window waits for it",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created},
			wantDue:       created,
			wantNextStart: nextSat,
		},
		{
			name:          "overdue, inside window",
			sched:         every30,
			in:            Input{Now: satInside, Created: created, LastRotation: new(at(istanbul, 9, 1, 3, 0))},
			wantStart:     true,
			wantDue:       at(istanbul, 10, 1, 3, 0),
			wantNextStart: satInside,
			wantWindowEnd: satWindowEnd,
		},
		{
			name:          "not due yet, due date falls outside window",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created, LastRotation: new(at(istanbul, 9, 28, 12, 0))},
			wantDue:       at(istanbul, 10, 28, 12, 0),
			wantNextStart: at(istanbul, 10, 31, 2, 0),
		},
		{
			name:          "not due yet, due date falls inside window",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created, LastRotation: new(at(istanbul, 9, 3, 3, 30))},
			wantDue:       at(istanbul, 10, 3, 3, 30),
			wantNextStart: at(istanbul, 10, 3, 3, 30),
		},
		{
			name:          "not due yet, inside window does not start",
			sched:         every30,
			in:            Input{Now: satInside, Created: created, LastRotation: new(at(istanbul, 9, 20, 3, 0))},
			wantDue:       at(istanbul, 10, 20, 3, 0),
			wantNextStart: at(istanbul, 10, 24, 2, 0),
			wantWindowEnd: satWindowEnd,
		},
		{
			name:          "overdue, too little window left waits for next window",
			sched:         every30,
			in:            Input{Now: at(istanbul, 10, 3, 4, 50), Created: created},
			wantDue:       created,
			wantNextStart: at(istanbul, 10, 4, 2, 0),
			wantWindowEnd: satWindowEnd,
		},
		{
			name:          "ignore-window also ignores minRemaining",
			sched:         every30,
			in:            Input{Now: at(istanbul, 10, 3, 4, 50), Created: created, IgnoreWindow: true},
			wantStart:     true,
			wantDue:       created,
			wantNextStart: at(istanbul, 10, 3, 4, 50),
			wantWindowEnd: satWindowEnd,
		},
		{
			name:          "due in the window's tail moves to next window",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created, LastRotation: new(at(istanbul, 9, 3, 4, 55))},
			wantDue:       at(istanbul, 10, 3, 4, 55),
			wantNextStart: at(istanbul, 10, 4, 2, 0),
		},
		{
			name:          "rotate-now still respects window",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created, LastRotation: new(at(istanbul, 9, 28, 12, 0)), RotateNow: true},
			wantDue:       tuesday,
			wantNextStart: nextSat,
		},
		{
			name:          "rotate-now with ignore-window starts immediately",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created, LastRotation: new(at(istanbul, 9, 28, 12, 0)), RotateNow: true, IgnoreWindow: true},
			wantStart:     true,
			wantDue:       tuesday,
			wantNextStart: tuesday,
		},
		{
			name:          "ignore-window alone does not make it due",
			sched:         every30,
			in:            Input{Now: tuesday, Created: created, LastRotation: new(at(istanbul, 9, 28, 12, 0)), IgnoreWindow: true},
			wantDue:       at(istanbul, 10, 28, 12, 0),
			wantNextStart: at(istanbul, 10, 31, 2, 0),
		},
		{
			name:          "cron tick inside window",
			sched:         krotosv1alpha1.Schedule{Cron: saturday3am},
			in:            Input{Now: at(istanbul, 10, 3, 3, 10), Created: created, LastRotation: new(at(istanbul, 9, 26, 3, 5))},
			wantStart:     true,
			wantDue:       at(istanbul, 10, 3, 3, 0),
			wantNextStart: at(istanbul, 10, 3, 3, 10),
			wantWindowEnd: satWindowEnd,
		},
		{
			name:          "missed cron window catches up at next window",
			sched:         krotosv1alpha1.Schedule{Cron: saturday3am},
			in:            Input{Now: at(istanbul, 10, 3, 6, 0), Created: created, LastRotation: new(at(istanbul, 9, 26, 3, 5))},
			wantDue:       at(istanbul, 10, 3, 3, 0),
			wantNextStart: at(istanbul, 10, 4, 2, 0),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := mustPlanner(t, tc.sched).Decide(tc.in)
			if d.Start != tc.wantStart {
				t.Errorf("Start = %v, want %v", d.Start, tc.wantStart)
			}
			if !d.Due.Equal(tc.wantDue) {
				t.Errorf("Due = %v, want %v", d.Due, tc.wantDue)
			}
			if !d.NextStart.Equal(tc.wantNextStart) {
				t.Errorf("NextStart = %v, want %v", d.NextStart, tc.wantNextStart)
			}
			if !d.WindowEnd.Equal(tc.wantWindowEnd) {
				t.Errorf("WindowEnd = %v, want %v", d.WindowEnd, tc.wantWindowEnd)
			}
			wantRequeue := time.Duration(0)
			if !tc.wantStart {
				wantRequeue = tc.wantNextStart.Sub(tc.in.Now)
			}
			if got := d.RequeueAfter(tc.in.Now); got != wantRequeue {
				t.Errorf("RequeueAfter = %v, want %v", got, wantRequeue)
			}
		})
	}
}

func TestPlannerMaxGap(t *testing.T) {
	from := at(istanbul, 10, 3, 2, 0) // Saturday, window start
	cases := map[string]struct {
		sched krotosv1alpha1.Schedule
		want  time.Duration
	}{
		"every 7 days": {krotosv1alpha1.Schedule{Every: "7d"}, 7 * 24 * time.Hour},
		// Due daily, but only weekends open: Sunday 03:00 to the next Saturday 02:00.
		"daily cron, weekend window": {krotosv1alpha1.Schedule{Cron: "0 3 * * *"}, 5*24*time.Hour + 23*time.Hour},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := mustPlanner(t, tc.sched).MaxGap(from); got != tc.want {
				t.Errorf("MaxGap = %v, want %v", got, tc.want)
			}
		})
	}
}
