package dtrack

import (
	"fmt"
	"strings"
	"time"
)

const (
	openEndMarker       = ".."
	maxPropertyValueLen = 255
)

// StageInterval represents a single ISO-8601 time interval (<Start>/<End>).
// If End == nil, the deployment is currently active in this stage (<Start>/..).
type StageInterval struct {
	Start time.Time
	End   *time.Time
}

// ParseStageIntervals parses a comma-separated ISO-8601 interval string, e.g.:
// "2026-10-01T10:00:00Z/2026-10-15T14:30:00Z,2026-10-20T08:00:00Z/.."
func ParseStageIntervals(raw string) ([]StageInterval, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	intervals := make([]StageInterval, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		bounds := strings.SplitN(part, "/", 2)
		start, err := time.Parse(time.RFC3339, strings.TrimSpace(bounds[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid interval start %q: %w", bounds[0], err)
		}

		var endPtr *time.Time
		if len(bounds) == 2 {
			endStr := strings.TrimSpace(bounds[1])
			if endStr != "" && endStr != openEndMarker {
				end, err := time.Parse(time.RFC3339, endStr)
				if err != nil {
					return nil, fmt.Errorf("invalid interval end %q: %w", endStr, err)
				}
				endUTC := end.UTC()
				endPtr = &endUTC
			}
		}

		intervals = append(intervals, StageInterval{
			Start: start.UTC(),
			End:   endPtr,
		})
	}

	return intervals, nil
}

// FormatStageIntervals serializes the intervals back into ISO-8601 format
// and ensures that Dependency-Track's 255-character limit is respected.
func FormatStageIntervals(intervals []StageInterval) string {
	if len(intervals) == 0 {
		return ""
	}

	formatSlice := func(slice []StageInterval) string {
		strs := make([]string, 0, len(slice))
		for _, iv := range slice {
			startStr := iv.Start.UTC().Format(time.RFC3339)
			if iv.End == nil {
				strs = append(strs, startStr+"/"+openEndMarker)
			} else {
				strs = append(strs, startStr+"/"+iv.End.UTC().Format(time.RFC3339))
			}
		}
		return strings.Join(strs, ",")
	}

	res := formatSlice(intervals)
	// Prevent VARCHAR(255) overflow in case of frequent rollbacks:
	// Always retain the very first interval (first_deployed_at) and the most recent intervals.
	for len(res) > maxPropertyValueLen && len(intervals) > 2 {
		intervals = append(intervals[:1], intervals[2:]...)
		res = formatSlice(intervals)
	}
	return res
}

// OpenStageInterval opens a new active interval if the project is not currently
// active in this stage (initial deployment or rollback).
// If it is already active (last interval is open-ended), it remains unchanged on pod restarts
// (or adopts an earlier start date if an existing ReplicaSet is older).
func OpenStageInterval(existingRaw string, candidateStart time.Time) string {
	if candidateStart.IsZero() {
		candidateStart = time.Now().UTC()
	} else {
		candidateStart = candidateStart.UTC()
	}

	intervals, err := ParseStageIntervals(existingRaw)
	if err != nil || len(intervals) == 0 {
		return FormatStageIntervals([]StageInterval{{Start: candidateStart, End: nil}})
	}

	last := &intervals[len(intervals)-1]
	if last.End == nil {
		// Project is already marked as active in this stage -> do not open a new interval.
		// If candidateStart is older (e.g., older ReplicaSet in a second namespace), adjust start time:
		if candidateStart.Before(last.Start) {
			last.Start = candidateStart
		}
		return FormatStageIntervals(intervals)
	}

	// Last interval was closed -> this is a rollback! Append a new open-ended interval:
	intervals = append(intervals, StageInterval{
		Start: candidateStart,
		End:   nil,
	})
	return FormatStageIntervals(intervals)
}

// CloseStageInterval closes the currently open interval when deactivating a project version.
func CloseStageInterval(existingRaw string, deactivatedAt time.Time) string {
	if deactivatedAt.IsZero() {
		deactivatedAt = time.Now().UTC()
	} else {
		deactivatedAt = deactivatedAt.UTC()
	}

	intervals, err := ParseStageIntervals(existingRaw)
	if err != nil || len(intervals) == 0 {
		return existingRaw
	}

	last := &intervals[len(intervals)-1]
	if last.End == nil {
		if deactivatedAt.Before(last.Start) {
			deactivatedAt = last.Start
		}
		last.End = &deactivatedAt
	}
	return FormatStageIntervals(intervals)
}

// IsActiveAt checks whether the project was active in this stage at timestamp t
// (can be used for historical trend calculations).
func IsActiveAt(intervals []StageInterval, t time.Time) bool {
	for _, iv := range intervals {
		if t.Before(iv.Start) {
			continue
		}
		if iv.End == nil || !t.After(*iv.End) {
			return true
		}
	}
	return false
}
