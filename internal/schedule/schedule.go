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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	krotosv1alpha1 "github.com/warewave/krotos/api/v1alpha1"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Schedule computes when the next rotation becomes due.
type Schedule interface {
	// NextDue returns when a rotation becomes due, given the reference time:
	// the last successful rotation, or the object's creation time if it never rotated.
	NextDue(reference time.Time, rotatedBefore bool) time.Time
}

// NewSchedule validates and converts the API representation of a schedule.
// Cron expressions are evaluated in loc.
func NewSchedule(spec krotosv1alpha1.Schedule, loc *time.Location) (Schedule, error) {
	switch {
	case spec.Cron != "" && spec.Every != "":
		return nil, errors.New("exactly one of cron or every must be set")
	case spec.Cron != "":
		expr := strings.TrimSpace(spec.Cron)
		if strings.HasPrefix(expr, "TZ=") || strings.HasPrefix(expr, "CRON_TZ=") {
			return nil, errors.New("cron must not contain a time zone; set window.timezone instead")
		}
		s, err := cronParser.Parse(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid cron %q: %w", spec.Cron, err)
		}
		return &cronSchedule{s: s, loc: loc}, nil
	case spec.Every != "":
		d, err := parseEvery(spec.Every)
		if err != nil {
			return nil, err
		}
		return &intervalSchedule{every: d}, nil
	default:
		return nil, errors.New("exactly one of cron or every must be set")
	}
}

// parseEvery parses "<N>d" or "<N>h".
func parseEvery(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid every %q: expected <N>d or <N>h", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid every %q: expected <N>d or <N>h", s)
	}
	switch s[len(s)-1] {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid every %q: expected <N>d or <N>h", s)
	}
}

type cronSchedule struct {
	s   cron.Schedule
	loc *time.Location
}

// NextDue is the first cron tick after the reference time.
func (c *cronSchedule) NextDue(reference time.Time, _ bool) time.Time {
	return c.s.Next(reference.In(c.loc))
}

type intervalSchedule struct {
	every time.Duration
}

// NextDue is reference+every; a rotation that never ran is due immediately.
func (i *intervalSchedule) NextDue(reference time.Time, rotatedBefore bool) time.Time {
	if !rotatedBefore {
		return reference
	}
	return reference.Add(i.every)
}
