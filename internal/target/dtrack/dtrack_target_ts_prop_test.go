package dtrack

import (
	"strings"
	"testing"
	"time"
)

func TestOpenStageInterval(t *testing.T) {
	t1 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 10, 15, 14, 30, 0, 0, time.UTC)
	t3 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		existingRaw    string
		candidateStart time.Time
		expected       string
	}{
		{
			name:           "1. Initial deployment (empty existing)",
			existingRaw:    "",
			candidateStart: t1,
			expected:       "2026-10-01T10:00:00Z/..",
		},
		{
			name:           "2. Already active (open interval remains unchanged)",
			existingRaw:    "2026-10-01T10:00:00Z/..",
			candidateStart: t2,
			expected:       "2026-10-01T10:00:00Z/..",
		},
		{
			name:           "3. Rollback after closed interval (appends new open interval)",
			existingRaw:    "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z",
			candidateStart: t3,
			expected:       "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z,2026-10-20T08:00:00Z/..",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OpenStageInterval(tc.existingRaw, tc.candidateStart)
			if got != tc.expected {
				t.Errorf("OpenStageInterval() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestCloseStageInterval(t *testing.T) {
	t1Start := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	t1End := time.Date(2026, 10, 15, 14, 30, 0, 0, time.UTC)

	tests := []struct {
		name          string
		existingRaw   string
		deactivatedAt time.Time
		expected      string
	}{
		{
			name:          "1. Close active open interval",
			existingRaw:   "2026-10-01T10:00:00Z/..",
			deactivatedAt: t1End,
			expected:      "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z",
		},
		{
			name:          "2. Already closed interval remains untouched",
			existingRaw:   "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z",
			deactivatedAt: t1End,
			expected:      "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CloseStageInterval(tc.existingRaw, tc.deactivatedAt)
			if got != tc.expected {
				t.Errorf("CloseStageInterval() = %v, want %v", got, tc.expected)
			}
			_ = t1Start
		})
	}
}

func TestIsActiveAt(t *testing.T) {
	// Interval: Oct 1 to Oct 15, and active again from Oct 20 onwards
	raw := "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z,2026-10-20T08:00:00Z/.."
	intervals, err := ParseStageIntervals(raw)
	if err != nil {
		t.Fatalf("Failed to parse intervals: %v", err)
	}

	tests := []struct {
		name   string
		checkT time.Time
		want   bool
	}{
		{
			name:   "Before first deployment",
			checkT: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
			want:   false,
		},
		{
			name:   "During first active period",
			checkT: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
			want:   true,
		},
		{
			name:   "During inactive period between update and rollback",
			checkT: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC),
			want:   false,
		},
		{
			name:   "During second active period (after rollback)",
			checkT: time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC),
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsActiveAt(intervals, tc.checkT)
			if got != tc.want {
				t.Errorf("IsActiveAt() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFormatStageIntervalsMaxLength(t *testing.T) {
	// Construct an interval list that would easily exceed 255 characters if not truncated
	var intervals []StageInterval
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 10; i++ {
		start := base.AddDate(0, i, 0)
		end := start.Add(24 * time.Hour)
		intervals = append(intervals, StageInterval{
			Start: start,
			End:   &end,
		})
	}
	// Add an open active interval at the end
	intervals = append(intervals, StageInterval{
		Start: base.AddDate(0, 11, 0),
		End:   nil,
	})

	formatted := FormatStageIntervals(intervals)

	if len(formatted) > maxPropertyValueLen {
		t.Errorf("Formatted string length %d exceeds maximum limit of %d characters", len(formatted), maxPropertyValueLen)
	}

	// Verify that the very first interval is preserved (crucial for initial deployment tracking)
	if !strings.HasPrefix(formatted, "2026-01-01T00:00:00Z/") {
		t.Errorf("Expected truncated string to preserve the first interval, got: %s", formatted)
	}
}
