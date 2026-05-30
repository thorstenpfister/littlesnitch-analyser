package filter

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		name    string
		filters Filters
		uid     int
		conn    string
		parent  string
		want    bool
	}{
		{"empty matches all", Filters{}, 0, "/bin/x", "", true},
		{"uid hit", Filters{UIDs: []int{0, 501}}, 501, "/bin/x", "", true},
		{"uid miss", Filters{UIDs: []int{0, 501}}, 65, "/bin/x", "", false},
		{"or within uid", Filters{UIDs: []int{0, 501}}, 0, "/bin/x", "", true},
		{"connecting exact hit", Filters{ConnectingExecutables: []string{"/bin/x"}}, 0, "/bin/x", "", true},
		{"connecting case sensitive miss", Filters{ConnectingExecutables: []string{"/bin/x"}}, 0, "/bin/X", "", false},
		{"parent hit", Filters{ParentExecutables: []string{"/App/P"}}, 0, "/bin/x", "/App/P", true},
		{"and across hit", Filters{UIDs: []int{0}, ParentExecutables: []string{"/App/P"}}, 0, "/bin/x", "/App/P", true},
		{"and across miss on parent", Filters{UIDs: []int{0}, ParentExecutables: []string{"/App/P"}}, 0, "/bin/x", "/App/Other", false},
		{"and across miss on uid", Filters{UIDs: []int{0}, ParentExecutables: []string{"/App/P"}}, 501, "/bin/x", "/App/P", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filters.Match(tc.uid, tc.conn, tc.parent); got != tc.want {
				t.Errorf("Match = %v, want %v", got, tc.want)
			}
		})
	}
}
