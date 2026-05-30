package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "update golden files")

const testdataDir = "../../testdata"

// fixedClock pins meta.generated_at so golden output is byte-stable.
func fixedClock() time.Time {
	return time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
}

func runCase(t *testing.T, args []string, inputFile string) (stdout, stderr string, code int) {
	t.Helper()
	in, err := os.ReadFile(filepath.Join(testdataDir, inputFile))
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}
	var out, errBuf bytes.Buffer
	code = run(bytes.NewReader(in), &out, &errBuf, args, fixedClock)
	return out.String(), errBuf.String(), code
}

func TestGolden(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		input  string
		golden string
	}{
		{"happy_path", nil, "happy_path.csv", "happy_path.golden.json"},
		{"empty_window", nil, "empty_window.csv", "empty_window.golden.json"},
		{"quoted_comma", nil, "quoted_comma.csv", "quoted_comma.golden.json"},
		{"malformed_row", nil, "malformed_row.csv", "malformed_row.golden.json"},
		{"delta_summation", nil, "delta_summation.csv", "delta_summation.golden.json"},
		{"reordered_header", nil, "reordered_header.csv", "reordered_header.golden.json"},
		{"sort_determinism", nil, "sort_determinism.csv", "sort_determinism.golden.json"},
		{"filter_uid", []string{"--uid", "0"}, "filters.csv", "filter_uid.golden.json"},
		{"filter_or_within", []string{"--uid", "0", "--uid", "501"}, "filters.csv", "filter_or_within.golden.json"},
		{"filter_connecting", []string{"--connecting-executable", "/usr/sbin/mDNSResponder"}, "filters.csv", "filter_connecting.golden.json"},
		{"filter_parent", []string{"--parent-executable", "/Applications/User.app/Contents/MacOS/User"}, "filters.csv", "filter_parent.golden.json"},
		{"filter_all_out", []string{"--uid", "0", "--parent-executable", "/Applications/User.app/Contents/MacOS/User"}, "filters.csv", "filter_all_out.golden.json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errBuf, code := runCase(t, tc.args, tc.input)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", code, errBuf)
			}
			goldenPath := filepath.Join(testdataDir, tc.golden)
			if *update {
				if err := os.WriteFile(goldenPath, []byte(out), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run with -update first): %v", err)
			}
			if out != string(want) {
				t.Errorf("output mismatch for %s.\n--- got ---\n%s\n--- want ---\n%s", tc.name, out, want)
			}
		})
	}
}

func TestExitCodes(t *testing.T) {
	t.Run("no_header", func(t *testing.T) {
		out, _, code := runCase(t, nil, "no_header.csv")
		if code != 3 {
			t.Errorf("exit = %d, want 3", code)
		}
		if out != "" {
			t.Errorf("expected no stdout on exit 3, got: %s", out)
		}
	})

	t.Run("bad_sort", func(t *testing.T) {
		_, _, code := runCase(t, []string{"--sort", "nonsense"}, "happy_path.csv")
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})

	t.Run("unknown_flag", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		code := run(bytes.NewReader(nil), &out, &errBuf, []string{"--bogus"}, fixedClock)
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})

	t.Run("version", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		code := run(bytes.NewReader(nil), &out, &errBuf, []string{"--version"}, fixedClock)
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		if out.String() == "" {
			t.Error("expected version on stdout")
		}
	})

	t.Run("help", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		code := run(bytes.NewReader(nil), &out, &errBuf, []string{"-h"}, fixedClock)
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})
}

func TestSortDeterminismRepeatable(t *testing.T) {
	out1, _, _ := runCase(t, nil, "sort_determinism.csv")
	out2, _, _ := runCase(t, nil, "sort_determinism.csv")
	if out1 != out2 {
		t.Error("identical input produced non-identical output")
	}
}

func TestReorderedHeaderMatchesHappyPath(t *testing.T) {
	hp, _, _ := runCase(t, nil, "happy_path.csv")
	ro, _, _ := runCase(t, nil, "reordered_header.csv")

	type doc struct {
		Totals      json.RawMessage `json:"totals"`
		Connections json.RawMessage `json:"connections"`
		Rollups     json.RawMessage `json:"rollups"`
	}
	var a, b doc
	if err := json.Unmarshal([]byte(hp), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(ro), &b); err != nil {
		t.Fatal(err)
	}
	if string(a.Totals) != string(b.Totals) {
		t.Errorf("totals differ:\n%s\nvs\n%s", a.Totals, b.Totals)
	}
	if string(a.Connections) != string(b.Connections) {
		t.Errorf("connections differ:\n%s\nvs\n%s", a.Connections, b.Connections)
	}
	if string(a.Rollups) != string(b.Rollups) {
		t.Errorf("rollups differ:\n%s\nvs\n%s", a.Rollups, b.Rollups)
	}
}
