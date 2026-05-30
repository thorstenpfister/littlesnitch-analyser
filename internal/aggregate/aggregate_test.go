package aggregate

import (
	"testing"
	"time"

	"github.com/thorstenpfister/littlesnitch-analyser/internal/parse"
)

func t0(h int) time.Time { return time.Date(2026, 5, 29, h, 0, 0, 0, time.UTC) }

func row(dir string, uid int, ip, host string, proto, port int, cc, dc, bin, bout int64, exe, parent string, when time.Time) parse.Row {
	return parse.Row{
		Date: when, Direction: dir, UID: uid, IPAddress: ip, RemoteHostname: host,
		Protocol: proto, Port: port, ConnectCount: cc, DenyCount: dc,
		ByteCountIn: bin, ByteCountOut: bout, ConnectingExecutable: exe, ParentAppExecutable: parent,
	}
}

func TestAddSumsAndWindow(t *testing.T) {
	a := New()
	a.Add(row("out", 501, "9.9.9.9", "svc", 6, 443, 1, 0, 100, 10, "/bin/app", "", t0(7)))
	a.Add(row("out", 501, "9.9.9.9", "svc", 6, 443, 2, 1, 200, 20, "/bin/app", "", t0(8)))
	a.Add(row("out", 501, "9.9.9.9", "svc", 6, 443, 3, 0, 50, 5, "/bin/app", "", t0(6)))

	res := a.Result(SortBytes)
	if len(res.Connections) != 1 {
		t.Fatalf("want 1 flow, got %d", len(res.Connections))
	}
	c := res.Connections[0]
	if c.ConnectCount != 6 || c.DenyCount != 1 || c.ByteCountIn != 350 || c.ByteCountOut != 35 {
		t.Errorf("sums wrong: %+v", c)
	}
	if !c.FirstSeen.Equal(t0(6)) || !c.LastSeen.Equal(t0(8)) {
		t.Errorf("window = %v..%v, want 06..08", c.FirstSeen, c.LastSeen)
	}
	if res.Totals.DistinctConnections != 1 || res.Totals.DistinctHosts != 1 || res.Totals.DistinctExecutables != 1 {
		t.Errorf("distinct counts wrong: %+v", res.Totals)
	}
	if len(res.Denied) != 1 {
		t.Errorf("denied should contain the flow (denyCount>0), got %d", len(res.Denied))
	}
}

func TestSortBytesDescWithTieBreak(t *testing.T) {
	a := New()
	// Equal total bytes (100) across three flows differing only by ipAddress.
	a.Add(row("out", 501, "1.1.1.3", "m", 6, 443, 0, 0, 50, 50, "/bin/m", "", t0(7)))
	a.Add(row("out", 501, "1.1.1.1", "z", 6, 443, 0, 0, 50, 50, "/bin/z", "", t0(7)))
	a.Add(row("out", 501, "1.1.1.2", "a", 6, 443, 0, 0, 50, 50, "/bin/a", "", t0(7)))
	res := a.Result(SortBytes)
	got := []string{res.Connections[0].IPAddress, res.Connections[1].IPAddress, res.Connections[2].IPAddress}
	want := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tiebreak order = %v, want %v", got, want)
			break
		}
	}
}

func TestSortMetricSelection(t *testing.T) {
	a := New()
	// big bytes, zero denies
	a.Add(row("out", 1, "1.1.1.1", "h1", 6, 443, 1, 0, 1000, 0, "/bin/bytes", "", t0(7)))
	// small bytes, many denies
	a.Add(row("out", 1, "2.2.2.2", "h2", 6, 443, 1, 9, 1, 0, "/bin/denies", "", t0(7)))

	byBytes := a.Result(SortBytes)
	if byBytes.Connections[0].ConnectingExecutable != "/bin/bytes" {
		t.Errorf("sort=bytes first = %s, want /bin/bytes", byBytes.Connections[0].ConnectingExecutable)
	}
	byDenies := a.Result(SortDenies)
	if byDenies.Connections[0].ConnectingExecutable != "/bin/denies" {
		t.Errorf("sort=denies first = %s, want /bin/denies", byDenies.Connections[0].ConnectingExecutable)
	}
}

func TestByDirectionAndHostFallback(t *testing.T) {
	a := New()
	a.Add(row("in", 65, "192.168.0.91", "", 17, 5353, 0, 0, 9777, 350, "/usr/sbin/mDNSResponder", "", t0(7)))
	a.Add(row("out", 501, "1.2.3.4", "h.example", 6, 443, 1, 0, 100, 64, "/bin/app", "", t0(7)))
	res := a.Result(SortBytes)

	if res.ByDirection.In.ByteCountIn != 9777 || res.ByDirection.Out.ByteCountOut != 64 {
		t.Errorf("by_direction wrong: %+v", res.ByDirection)
	}
	if res.ByDirection.In.DistinctConnections != 1 || res.ByDirection.Out.DistinctConnections != 1 {
		t.Errorf("by_direction distinct wrong: %+v", res.ByDirection)
	}

	// host with empty remoteHostname falls back to ipAddress and flags hostname_known=false.
	var ipHost *ByHost
	for i := range res.ByHost {
		if res.ByHost[i].Host == "192.168.0.91" {
			ipHost = &res.ByHost[i]
		}
	}
	if ipHost == nil {
		t.Fatal("expected by_host entry keyed by ipAddress fallback")
	}
	if ipHost.HostnameKnown {
		t.Error("hostname_known should be false for ip fallback")
	}
}
