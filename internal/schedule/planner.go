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
	"time"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

// Planner combines a schedule and a change window.
type Planner struct {
	Schedule Schedule
	Window   *Window
}

// NewPlanner validates the schedule and window of a rotation spec.
func NewPlanner(spec *krotosv1alpha1.DatabaseCredentialRotationSpec) (*Planner, error) {
	w, err := NewWindow(spec.Window)
	if err != nil {
		return nil, err
	}
	s, err := NewSchedule(spec.Schedule, w.Location())
	if err != nil {
		return nil, err
	}
	return &Planner{Schedule: s, Window: w}, nil
}

// Input is the state a decision is based on.
type Input struct {
	Now time.Time
	// Created is the object's creation time; the schedule reference before the first rotation.
	Created time.Time
	// LastRotation is the last successful rotation, nil if it never rotated.
	LastRotation *time.Time
	// RotateNow makes the rotation due immediately (manual trigger).
	RotateNow bool
	// IgnoreWindow lets a due rotation start outside the change window.
	IgnoreWindow bool
}

// Decision tells the controller what to do.
type Decision struct {
	// Start is true when a rotation should start now.
	Start bool
	// Due is when the rotation became or becomes due.
	Due time.Time
	// NextStart is the earliest time the rotation may start: Now when Start is true,
	// otherwise the first moment at or after Due that is inside a window with at
	// least minRemaining left.
	NextStart time.Time
	// WindowEnd is when the current window closes. Zero when not inside a window.
	WindowEnd time.Time
}

// RequeueAfter is how long to wait before the next start is possible.
func (d Decision) RequeueAfter(now time.Time) time.Duration {
	if d.Start || !d.NextStart.After(now) {
		return 0
	}
	return d.NextStart.Sub(now)
}

// Decide evaluates whether a rotation should start now.
func (p *Planner) Decide(in Input) Decision {
	var due time.Time
	switch {
	case in.RotateNow:
		due = in.Now
	case in.LastRotation != nil:
		due = p.Schedule.NextDue(*in.LastRotation, true)
	default:
		due = p.Schedule.NextDue(in.Created, false)
	}

	d := Decision{Due: due}
	if end, ok := p.Window.Contains(in.Now); ok {
		d.WindowEnd = end
	}

	if due.After(in.Now) {
		d.NextStart = p.Window.NextStart(due)
		return d
	}

	if in.IgnoreWindow || p.Window.CanStart(in.Now) {
		d.Start = true
		d.NextStart = in.Now
		return d
	}

	d.NextStart = p.Window.NextStart(in.Now)
	return d
}
