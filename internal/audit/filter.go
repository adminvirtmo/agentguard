package audit

import (
	"fmt"
	"slices"
	"time"
)

var validStatuses = []string{"allowed", "blocked", "confirmed", "denied", "failed"}

func ValidStatus(status string) bool {
	return status == "" || slices.Contains(validStatuses, status)
}

func StatusNames() []string {
	return append([]string(nil), validStatuses...)
}

func Filter(events []Event, status string, since time.Time) []Event {
	if status == "" && since.IsZero() {
		return events
	}
	var filtered []Event
	for _, e := range events {
		if status != "" && e.Status != status {
			continue
		}
		if !since.IsZero() {
			t, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil || t.Before(since) {
				continue
			}
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func ParseSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid since value %q: use duration, RFC3339, or YYYY-MM-DD", value)
}
