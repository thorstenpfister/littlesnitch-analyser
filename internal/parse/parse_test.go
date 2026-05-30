package parse

import (
	"errors"
	"testing"
	"time"
)

var canonicalHeader = []string{
	"date", "direction", "uid", "ipAddress", "remoteHostname",
	"protocol", "port", "connectCount", "denyCount",
	"byteCountIn", "byteCountOut", "connectingExecutable", "parentAppExecutable",
}

func TestNewHeaderMissingColumn(t *testing.T) {
	short := canonicalHeader[:len(canonicalHeader)-1] // drop parentAppExecutable
	_, err := NewHeader(short)
	var mce *MissingColumnsError
	if !errors.As(err, &mce) {
		t.Fatalf("want MissingColumnsError, got %v", err)
	}
	if len(mce.Missing) != 1 || mce.Missing[0] != "parentAppExecutable" {
		t.Errorf("missing = %v, want [parentAppExecutable]", mce.Missing)
	}
}

func TestNewHeaderReorderedAndExtra(t *testing.T) {
	reordered := []string{
		"connectingExecutable", "extra", "date", "direction", "uid", "ipAddress",
		"remoteHostname", "protocol", "port", "connectCount", "denyCount",
		"byteCountIn", "byteCountOut", "parentAppExecutable",
	}
	h, err := NewHeader(reordered)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec := []string{
		"/bin/x", "ignored",
		"2026-05-29T07:00:00Z", "out", "501", "1.2.3.4", "host.example",
		"6", "443", "0", "0", "100", "200", "/App/Parent",
	}
	keys, err := h.DecodeKeys(rec)
	if err != nil {
		t.Fatalf("DecodeKeys: %v", err)
	}
	if keys.ConnectingExecutable != "/bin/x" {
		t.Errorf("connectingExecutable = %q, want /bin/x (name-based mapping broke)", keys.ConnectingExecutable)
	}
}

func TestDecodeKeysAndRow(t *testing.T) {
	h, err := NewHeader(canonicalHeader)
	if err != nil {
		t.Fatal(err)
	}
	rec := []string{
		"2026-05-29T07:00:00Z", "out", "501", "1.2.3.4", "host.example",
		"6", "443", "3", "1", "100", "200", "/bin/app", "/App/Parent",
	}
	keys, err := h.DecodeKeys(rec)
	if err != nil {
		t.Fatalf("DecodeKeys: %v", err)
	}
	if keys.UID != 501 || keys.ConnectingExecutable != "/bin/app" || keys.ParentAppExecutable != "/App/Parent" {
		t.Errorf("keys = %+v", keys)
	}
	if !keys.Date.Equal(time.Date(2026, 5, 29, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("date = %v", keys.Date)
	}
	row, err := h.DecodeRow(rec, keys)
	if err != nil {
		t.Fatalf("DecodeRow: %v", err)
	}
	if row.Protocol != 6 || row.Port != 443 || row.ConnectCount != 3 || row.DenyCount != 1 ||
		row.ByteCountIn != 100 || row.ByteCountOut != 200 {
		t.Errorf("row = %+v", row)
	}
}

func TestDecodeErrors(t *testing.T) {
	h, _ := NewHeader(canonicalHeader)
	base := []string{
		"2026-05-29T07:00:00Z", "out", "501", "1.2.3.4", "host.example",
		"6", "443", "0", "0", "100", "200", "/bin/app", "",
	}

	t.Run("bad uid is a key error", func(t *testing.T) {
		rec := append([]string(nil), base...)
		rec[2] = "abc"
		if _, err := h.DecodeKeys(rec); err == nil {
			t.Error("want uid parse error")
		}
	})
	t.Run("bad date is a key error", func(t *testing.T) {
		rec := append([]string(nil), base...)
		rec[0] = "not-a-date"
		if _, err := h.DecodeKeys(rec); err == nil {
			t.Error("want date parse error")
		}
	})
	t.Run("bad counter is a row error", func(t *testing.T) {
		rec := append([]string(nil), base...)
		rec[9] = "oops"
		keys, err := h.DecodeKeys(rec)
		if err != nil {
			t.Fatalf("DecodeKeys should succeed: %v", err)
		}
		if _, err := h.DecodeRow(rec, keys); err == nil {
			t.Error("want byteCountIn parse error")
		}
	})
}

func TestProtocolName(t *testing.T) {
	cases := map[int]string{1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 999: "proto-999"}
	for n, want := range cases {
		if got := ProtocolName(n); got != want {
			t.Errorf("ProtocolName(%d) = %q, want %q", n, got, want)
		}
	}
}
