package audit

import (
	"testing"
	"time"
)

func TestFilterByStatusAndSince(t *testing.T) {
	events := []Event{
		{Timestamp: "2026-06-19T10:00:00Z", Status: "allowed", Command: "git status"},
		{Timestamp: "2026-06-19T12:00:00Z", Status: "blocked", Command: "cat .env"},
	}
	since := time.Date(2026, 6, 19, 11, 0, 0, 0, time.UTC)
	got := Filter(events, "blocked", since)
	if len(got) != 1 || got[0].Command != "cat .env" {
		t.Fatalf("unexpected filtered events: %#v", got)
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	got, err := ParseSince("2h", now)
	if err != nil {
		t.Fatalf("ParseSince duration: %v", err)
	}
	if !got.Equal(now.Add(-2 * time.Hour)) {
		t.Fatalf("duration since = %s", got)
	}
	if _, err := ParseSince("2026-06-19", now); err != nil {
		t.Fatalf("ParseSince date: %v", err)
	}
	if _, err := ParseSince("bad", now); err == nil {
		t.Fatal("expected invalid since error")
	}
}
