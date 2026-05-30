// Package filter applies the inclusion filters to decoded rows before aggregation.
package filter

import "slices"

// Filters holds the active inclusion filters. Within a single slice the values OR
// together; across the three slices the conditions AND together. An empty slice
// imposes no constraint on its field. Matching is exact, case-sensitive, full-value.
type Filters struct {
	UIDs                  []int
	ConnectingExecutables []string
	ParentExecutables     []string
}

// Match reports whether a row with the given fields passes every active filter.
func (f Filters) Match(uid int, connectingExecutable, parentExecutable string) bool {
	if len(f.UIDs) > 0 && !slices.Contains(f.UIDs, uid) {
		return false
	}
	if len(f.ConnectingExecutables) > 0 && !slices.Contains(f.ConnectingExecutables, connectingExecutable) {
		return false
	}
	if len(f.ParentExecutables) > 0 && !slices.Contains(f.ParentExecutables, parentExecutable) {
		return false
	}
	return true
}
