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

// Package schedule decides when a rotation is due and whether it may start,
// based on the rotation schedule and the mandatory change window.
package schedule

import (
	"fmt"
	"time"

	// Embed the time zone database so window time zones resolve regardless of
	// what the container image ships.
	_ "time/tzdata"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

const maxWindowDuration = 24 * time.Hour

var weekdays = map[krotosv1alpha1.Weekday]time.Weekday{
	"Sun": time.Sunday,
	"Mon": time.Monday,
	"Tue": time.Tuesday,
	"Wed": time.Wednesday,
	"Thu": time.Thursday,
	"Fri": time.Friday,
	"Sat": time.Saturday,
}

// Window is a recurring change window. A window belongs to the day it opens on,
// so a window opening Saturday 23:00 for 3h lasts until Sunday 02:00.
type Window struct {
	loc          *time.Location
	days         [7]bool
	hour         int
	minute       int
	duration     time.Duration
	minRemaining time.Duration
}

// NewWindow validates and converts the API representation of a change window.
func NewWindow(spec krotosv1alpha1.MaintenanceWindow) (*Window, error) {
	tz := spec.Timezone
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("invalid window timezone %q: %w", tz, err)
	}

	start, err := time.Parse("15:04", spec.Start)
	if err != nil {
		return nil, fmt.Errorf("invalid window start %q: expected HH:MM", spec.Start)
	}

	d := spec.Duration.Duration
	if d <= 0 || d > maxWindowDuration {
		return nil, fmt.Errorf("invalid window duration %s: must be greater than 0 and at most 24h", d)
	}

	minRemaining := spec.MinRemaining.Duration
	if minRemaining < 0 || minRemaining >= d {
		return nil, fmt.Errorf("invalid window minRemaining %s: must be at least 0 and shorter than duration", minRemaining)
	}

	w := &Window{loc: loc, hour: start.Hour(), minute: start.Minute(), duration: d, minRemaining: minRemaining}
	if len(spec.Days) == 0 {
		for i := range w.days {
			w.days[i] = true
		}
	}
	for _, day := range spec.Days {
		wd, ok := weekdays[day]
		if !ok {
			return nil, fmt.Errorf("invalid window day %q", day)
		}
		w.days[wd] = true
	}
	return w, nil
}

// Location returns the window's time zone.
func (w *Window) Location() *time.Location {
	return w.loc
}

// openingOn returns the window that opens on the calendar day of t (in the
// window's time zone), if the window opens on that weekday. A start time that
// does not exist because of a DST jump is moved forward by the jump.
func (w *Window) openingOn(t time.Time) (start, end time.Time, ok bool) {
	t = t.In(w.loc)
	if !w.days[t.Weekday()] {
		return time.Time{}, time.Time{}, false
	}
	start = time.Date(t.Year(), t.Month(), t.Day(), w.hour, w.minute, 0, 0, w.loc)
	return start, start.Add(w.duration), true
}

// Contains reports whether t is inside an open window, and if so when that window closes.
func (w *Window) Contains(t time.Time) (end time.Time, ok bool) {
	// Windows are at most 24h long, so only windows opening today or yesterday can cover t.
	local := t.In(w.loc)
	for _, day := range []time.Time{local, local.AddDate(0, 0, -1)} {
		start, end, ok := w.openingOn(day)
		if ok && !t.Before(start) && t.Before(end) {
			return end, true
		}
	}
	return time.Time{}, false
}

// NextOpen returns the earliest instant at or after t that lies inside a window.
func (w *Window) NextOpen(t time.Time) time.Time {
	if _, ok := w.Contains(t); ok {
		return t
	}
	local := t.In(w.loc)
	// Every weekday is reachable within 7 days; the 8th covers today's start having passed.
	for i := 0; i <= 7; i++ {
		start, _, ok := w.openingOn(local.AddDate(0, 0, i))
		if ok && start.After(t) {
			return start
		}
	}
	// Unreachable: NewWindow guarantees at least one day is enabled.
	panic("schedule: window has no enabled days")
}

// CanStart reports whether a rotation may start at t: t is inside a window and
// at least minRemaining is left before it closes.
func (w *Window) CanStart(t time.Time) bool {
	end, ok := w.Contains(t)
	return ok && end.Sub(t) >= w.minRemaining
}

// NextStart returns the earliest instant at or after t at which a rotation may start.
func (w *Window) NextStart(t time.Time) time.Time {
	// minRemaining < duration, so the next opening always qualifies; the loop only
	// skips the tail of the window t is in. Back-to-back windows may need a few hops.
	for {
		t = w.NextOpen(t)
		end, _ := w.Contains(t)
		if end.Sub(t) >= w.minRemaining {
			return t
		}
		t = end
	}
}
