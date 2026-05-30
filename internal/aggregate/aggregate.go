// Package aggregate collapses decoded rows into per-flow records and derives every
// rollup from that single source of truth, so all reported numbers reconcile.
package aggregate

import (
	"cmp"
	"slices"
	"time"

	"github.com/thorstenpfister/littlesnitch-analyser/internal/parse"
)

// SortKey selects the primary ordering metric for the connections array and the
// by_executable / by_host rollups.
type SortKey string

const (
	SortBytes    SortKey = "bytes"
	SortConnects SortKey = "connects"
	SortDenies   SortKey = "denies"
)

// FlowKey is the full tuple that identifies one distinct flow. It is comparable so
// it can be used directly as a map key.
type FlowKey struct {
	Direction            string
	UID                  int
	IPAddress            string
	RemoteHostname       string
	Protocol             int
	Port                 int
	ConnectingExecutable string
	ParentAppExecutable  string
}

// Flow accumulates the four counters and the seen-window for one FlowKey.
type Flow struct {
	ByteCountIn  int64
	ByteCountOut int64
	ConnectCount int64
	DenyCount    int64
	FirstSeen    time.Time
	LastSeen     time.Time
}

type Aggregator struct {
	flows map[FlowKey]*Flow
}

// New returns an empty Aggregator.
func New() *Aggregator {
	return &Aggregator{flows: make(map[FlowKey]*Flow)}
}

// Add folds one decoded row into its flow, summing counters and widening the
// first/last-seen window.
func (a *Aggregator) Add(r parse.Row) {
	key := FlowKey{
		Direction:            r.Direction,
		UID:                  r.UID,
		IPAddress:            r.IPAddress,
		RemoteHostname:       r.RemoteHostname,
		Protocol:             r.Protocol,
		Port:                 r.Port,
		ConnectingExecutable: r.ConnectingExecutable,
		ParentAppExecutable:  r.ParentAppExecutable,
	}
	f := a.flows[key]
	if f == nil {
		f = &Flow{FirstSeen: r.Date, LastSeen: r.Date}
		a.flows[key] = f
	}
	f.ByteCountIn += r.ByteCountIn
	f.ByteCountOut += r.ByteCountOut
	f.ConnectCount += r.ConnectCount
	f.DenyCount += r.DenyCount
	if r.Date.Before(f.FirstSeen) {
		f.FirstSeen = r.Date
	}
	if r.Date.After(f.LastSeen) {
		f.LastSeen = r.Date
	}
}

// Connection is one flow flattened for output (also reused for the denied list).
type Connection struct {
	FlowKey
	ByteCountIn  int64
	ByteCountOut int64
	ConnectCount int64
	DenyCount    int64
	FirstSeen    time.Time
	LastSeen     time.Time
}

// Totals are the post-filter grand totals.
type Totals struct {
	ByteCountIn         int64
	ByteCountOut        int64
	ConnectCount        int64
	DenyCount           int64
	DistinctConnections int
	DistinctHosts       int
	DistinctExecutables int
}

// ByExecutable is one row of the by_executable rollup.
type ByExecutable struct {
	ConnectingExecutable string
	ParentAppExecutable  string
	ByteCountIn          int64
	ByteCountOut         int64
	ConnectCount         int64
	DenyCount            int64
	DistinctHosts        int
	DistinctConnections  int
}

// ByHost is one row of the by_host rollup.
type ByHost struct {
	Host                string
	HostnameKnown       bool
	ByteCountIn         int64
	ByteCountOut        int64
	ConnectCount        int64
	DenyCount           int64
	DistinctExecutables int
}

// DirectionAgg is one direction bucket of the by_direction rollup.
type DirectionAgg struct {
	ByteCountIn         int64
	ByteCountOut        int64
	ConnectCount        int64
	DenyCount           int64
	DistinctConnections int
}

// ByDirection holds the fixed in/out buckets.
type ByDirection struct {
	In  DirectionAgg
	Out DirectionAgg
}

// Result is the complete derived view, ready for rendering.
type Result struct {
	Totals       Totals
	Connections  []Connection
	ByExecutable []ByExecutable
	ByHost       []ByHost
	ByDirection  ByDirection
	Denied       []Connection
}

// Result derives every aggregate view from the flow map, ordered per sort.
func (a *Aggregator) Result(sort SortKey) Result {
	var res Result

	totalHosts := make(map[string]struct{})
	totalExes := make(map[string]struct{})

	type execAcc struct {
		parents                   map[string]struct{}
		hosts                     map[string]struct{}
		conns                     int
		in, out, connects, denies int64
	}
	execs := make(map[string]*execAcc)

	type hostAcc struct {
		known                     bool
		exes                      map[string]struct{}
		in, out, connects, denies int64
	}
	hosts := make(map[string]*hostAcc)

	for key, f := range a.flows {
		res.Totals.ByteCountIn += f.ByteCountIn
		res.Totals.ByteCountOut += f.ByteCountOut
		res.Totals.ConnectCount += f.ConnectCount
		res.Totals.DenyCount += f.DenyCount

		dh := displayHost(key)
		totalHosts[dh] = struct{}{}
		totalExes[key.ConnectingExecutable] = struct{}{}

		conn := Connection{
			FlowKey:      key,
			ByteCountIn:  f.ByteCountIn,
			ByteCountOut: f.ByteCountOut,
			ConnectCount: f.ConnectCount,
			DenyCount:    f.DenyCount,
			FirstSeen:    f.FirstSeen,
			LastSeen:     f.LastSeen,
		}
		res.Connections = append(res.Connections, conn)
		if f.DenyCount > 0 {
			res.Denied = append(res.Denied, conn)
		}

		switch key.Direction {
		case "in":
			addDirection(&res.ByDirection.In, f)
			res.ByDirection.In.DistinctConnections++
		case "out":
			addDirection(&res.ByDirection.Out, f)
			res.ByDirection.Out.DistinctConnections++
		}

		ea := execs[key.ConnectingExecutable]
		if ea == nil {
			ea = &execAcc{parents: map[string]struct{}{}, hosts: map[string]struct{}{}}
			execs[key.ConnectingExecutable] = ea
		}
		ea.in += f.ByteCountIn
		ea.out += f.ByteCountOut
		ea.connects += f.ConnectCount
		ea.denies += f.DenyCount
		ea.conns++
		ea.hosts[dh] = struct{}{}
		if key.ParentAppExecutable != "" {
			ea.parents[key.ParentAppExecutable] = struct{}{}
		}

		ha := hosts[dh]
		if ha == nil {
			ha = &hostAcc{exes: map[string]struct{}{}}
			hosts[dh] = ha
		}
		ha.in += f.ByteCountIn
		ha.out += f.ByteCountOut
		ha.connects += f.ConnectCount
		ha.denies += f.DenyCount
		ha.exes[key.ConnectingExecutable] = struct{}{}
		if key.RemoteHostname != "" {
			ha.known = true
		}
	}

	res.Totals.DistinctConnections = len(a.flows)
	res.Totals.DistinctHosts = len(totalHosts)
	res.Totals.DistinctExecutables = len(totalExes)

	for exe, ea := range execs {
		res.ByExecutable = append(res.ByExecutable, ByExecutable{
			ConnectingExecutable: exe,
			ParentAppExecutable:  minKey(ea.parents),
			ByteCountIn:          ea.in,
			ByteCountOut:         ea.out,
			ConnectCount:         ea.connects,
			DenyCount:            ea.denies,
			DistinctHosts:        len(ea.hosts),
			DistinctConnections:  ea.conns,
		})
	}
	for host, ha := range hosts {
		res.ByHost = append(res.ByHost, ByHost{
			Host:                host,
			HostnameKnown:       ha.known,
			ByteCountIn:         ha.in,
			ByteCountOut:        ha.out,
			ConnectCount:        ha.connects,
			DenyCount:           ha.denies,
			DistinctExecutables: len(ha.exes),
		})
	}

	connMetric := func(c Connection) int64 {
		return metricValue(sort, c.ByteCountIn, c.ByteCountOut, c.ConnectCount, c.DenyCount)
	}
	sortDesc(res.Connections, connMetric, func(a, b Connection) int { return compareKey(a.FlowKey, b.FlowKey) })
	sortDesc(res.Denied, func(c Connection) int64 { return c.DenyCount },
		func(a, b Connection) int { return compareKey(a.FlowKey, b.FlowKey) })
	sortDesc(res.ByExecutable,
		func(e ByExecutable) int64 {
			return metricValue(sort, e.ByteCountIn, e.ByteCountOut, e.ConnectCount, e.DenyCount)
		},
		func(a, b ByExecutable) int {
			return cmp.Or(
				cmp.Compare(a.ConnectingExecutable, b.ConnectingExecutable),
				cmp.Compare(a.ParentAppExecutable, b.ParentAppExecutable),
			)
		})
	sortDesc(res.ByHost,
		func(h ByHost) int64 {
			return metricValue(sort, h.ByteCountIn, h.ByteCountOut, h.ConnectCount, h.DenyCount)
		},
		func(a, b ByHost) int { return cmp.Compare(a.Host, b.Host) })

	// Guarantee non-nil slices so JSON renders [] rather than null.
	if res.Connections == nil {
		res.Connections = []Connection{}
	}
	if res.Denied == nil {
		res.Denied = []Connection{}
	}
	if res.ByExecutable == nil {
		res.ByExecutable = []ByExecutable{}
	}
	if res.ByHost == nil {
		res.ByHost = []ByHost{}
	}
	return res
}

func addDirection(d *DirectionAgg, f *Flow) {
	d.ByteCountIn += f.ByteCountIn
	d.ByteCountOut += f.ByteCountOut
	d.ConnectCount += f.ConnectCount
	d.DenyCount += f.DenyCount
}

func displayHost(k FlowKey) string {
	if k.RemoteHostname != "" {
		return k.RemoteHostname
	}
	return k.IPAddress
}

func minKey(set map[string]struct{}) string {
	first := true
	var min string
	for s := range set {
		if first || s < min {
			min, first = s, false
		}
	}
	return min
}

func metricValue(s SortKey, in, out, connects, denies int64) int64 {
	switch s {
	case SortConnects:
		return connects
	case SortDenies:
		return denies
	default:
		return in + out
	}
}

func compareKey(a, b FlowKey) int {
	return cmp.Or(
		cmp.Compare(a.Direction, b.Direction),
		cmp.Compare(a.UID, b.UID),
		cmp.Compare(a.IPAddress, b.IPAddress),
		cmp.Compare(a.RemoteHostname, b.RemoteHostname),
		cmp.Compare(a.Protocol, b.Protocol),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.ConnectingExecutable, b.ConnectingExecutable),
		cmp.Compare(a.ParentAppExecutable, b.ParentAppExecutable),
	)
}

// sortDesc orders s by primary metric descending, with tie-break left to the caller.
func sortDesc[T any](s []T, primary func(T) int64, tie func(a, b T) int) {
	slices.SortFunc(s, func(a, b T) int {
		if c := cmp.Compare(primary(b), primary(a)); c != 0 {
			return c
		}
		return tie(a, b)
	})
}
