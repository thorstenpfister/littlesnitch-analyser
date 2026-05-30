// Package output owns the canonical JSON document: its exact field order, the
// mapping from aggregate results, and the deterministic encoder. It also renders
// the secondary --human table.
package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/thorstenpfister/littlesnitch-analyser/internal/aggregate"
	"github.com/thorstenpfister/littlesnitch-analyser/internal/parse"
)

// Document is the single top-level JSON object. Field order here is the wire order.
type Document struct {
	Meta        Meta         `json:"meta"`
	Totals      Totals       `json:"totals"`
	Connections []Connection `json:"connections"`
	Rollups     Rollups      `json:"rollups"`
	SkippedRows []SkippedRow `json:"skipped_rows"`
}

// Meta describes the run and the lens applied to the data.
type Meta struct {
	Tool              string         `json:"tool"`
	ToolVersion       string         `json:"tool_version"`
	GeneratedAt       string         `json:"generated_at"`
	ObservedWindow    ObservedWindow `json:"observed_window"`
	Filters           Filters        `json:"filters"`
	CSVColumns        []string       `json:"csv_columns"`
	RowsTotal         int            `json:"rows_total"`
	RowsMatchedFilter int            `json:"rows_matched_filter"`
	RowsParsed        int            `json:"rows_parsed"`
	RowsSkipped       int            `json:"rows_skipped"`
}

// ObservedWindow reports the min/max row date actually seen (null when no dated rows).
type ObservedWindow struct {
	FirstRowDate *string `json:"first_row_date"`
	LastRowDate  *string `json:"last_row_date"`
}

// Filters records the active inclusion filters (always arrays, never null).
type Filters struct {
	UID                  []int    `json:"uid"`
	ConnectingExecutable []string `json:"connecting_executable"`
	ParentExecutable     []string `json:"parent_executable"`
}

// Totals are the post-filter grand totals.
type Totals struct {
	ByteCountIn         int64 `json:"byteCountIn"`
	ByteCountOut        int64 `json:"byteCountOut"`
	ConnectCount        int64 `json:"connectCount"`
	DenyCount           int64 `json:"denyCount"`
	DistinctConnections int   `json:"distinct_connections"`
	DistinctHosts       int   `json:"distinct_hosts"`
	DistinctExecutables int   `json:"distinct_executables"`
}

// Connection is one flow (also used for the denied list).
type Connection struct {
	Direction            string `json:"direction"`
	UID                  int    `json:"uid"`
	IPAddress            string `json:"ipAddress"`
	RemoteHostname       string `json:"remoteHostname"`
	HostnameKnown        bool   `json:"hostname_known"`
	Protocol             int    `json:"protocol"`
	ProtocolName         string `json:"protocolName"`
	Port                 int    `json:"port"`
	ConnectingExecutable string `json:"connectingExecutable"`
	ParentAppExecutable  string `json:"parentAppExecutable"`
	ConnectCount         int64  `json:"connectCount"`
	DenyCount            int64  `json:"denyCount"`
	ByteCountIn          int64  `json:"byteCountIn"`
	ByteCountOut         int64  `json:"byteCountOut"`
	FirstSeen            string `json:"firstSeen"`
	LastSeen             string `json:"lastSeen"`
}

// Rollups groups the derived views.
type Rollups struct {
	ByExecutable []ByExecutable `json:"by_executable"`
	ByHost       []ByHost       `json:"by_host"`
	ByDirection  ByDirection    `json:"by_direction"`
	Denied       []Connection   `json:"denied"`
}

// ByExecutable is one row of the by_executable rollup.
type ByExecutable struct {
	ConnectingExecutable string `json:"connectingExecutable"`
	ParentAppExecutable  string `json:"parentAppExecutable"`
	ByteCountIn          int64  `json:"byteCountIn"`
	ByteCountOut         int64  `json:"byteCountOut"`
	ConnectCount         int64  `json:"connectCount"`
	DenyCount            int64  `json:"denyCount"`
	DistinctHosts        int    `json:"distinct_hosts"`
	DistinctConnections  int    `json:"distinct_connections"`
}

// ByHost is one row of the by_host rollup.
type ByHost struct {
	Host                string `json:"host"`
	HostnameKnown       bool   `json:"hostname_known"`
	ByteCountIn         int64  `json:"byteCountIn"`
	ByteCountOut        int64  `json:"byteCountOut"`
	ConnectCount        int64  `json:"connectCount"`
	DenyCount           int64  `json:"denyCount"`
	DistinctExecutables int    `json:"distinct_executables"`
}

// DirectionAgg is one bucket of the by_direction rollup.
type DirectionAgg struct {
	ByteCountIn         int64 `json:"byteCountIn"`
	ByteCountOut        int64 `json:"byteCountOut"`
	ConnectCount        int64 `json:"connectCount"`
	DenyCount           int64 `json:"denyCount"`
	DistinctConnections int   `json:"distinct_connections"`
}

// ByDirection holds the fixed in/out buckets.
type ByDirection struct {
	In  DirectionAgg `json:"in"`
	Out DirectionAgg `json:"out"`
}

// SkippedRow surfaces a row that failed to parse, never silently dropped.
type SkippedRow struct {
	Line  int    `json:"line"`
	Raw   string `json:"raw"`
	Error string `json:"error"`
}

// BuildInput carries everything Build needs from the caller; the aggregate Result
// supplies the data, the rest supplies the meta lens.
type BuildInput struct {
	ToolVersion  string
	GeneratedAt  time.Time
	FirstRowDate *time.Time
	LastRowDate  *time.Time
	Filters      Filters
	CSVColumns   []string
	RowsTotal    int
	RowsMatched  int
	RowsParsed   int
	RowsSkipped  int
	Result       aggregate.Result
	Skipped      []SkippedRow
}

// Build assembles the wire Document from aggregate output and run metadata.
func Build(in BuildInput) Document {
	doc := Document{
		Meta: Meta{
			Tool:        "littlesnitch-analyser",
			ToolVersion: in.ToolVersion,
			GeneratedAt: rfc3339(in.GeneratedAt),
			ObservedWindow: ObservedWindow{
				FirstRowDate: ptrTime(in.FirstRowDate),
				LastRowDate:  ptrTime(in.LastRowDate),
			},
			Filters: Filters{
				UID:                  nonNil(in.Filters.UID),
				ConnectingExecutable: nonNil(in.Filters.ConnectingExecutable),
				ParentExecutable:     nonNil(in.Filters.ParentExecutable),
			},
			CSVColumns:        nonNil(in.CSVColumns),
			RowsTotal:         in.RowsTotal,
			RowsMatchedFilter: in.RowsMatched,
			RowsParsed:        in.RowsParsed,
			RowsSkipped:       in.RowsSkipped,
		},
		Totals: Totals{
			ByteCountIn:         in.Result.Totals.ByteCountIn,
			ByteCountOut:        in.Result.Totals.ByteCountOut,
			ConnectCount:        in.Result.Totals.ConnectCount,
			DenyCount:           in.Result.Totals.DenyCount,
			DistinctConnections: in.Result.Totals.DistinctConnections,
			DistinctHosts:       in.Result.Totals.DistinctHosts,
			DistinctExecutables: in.Result.Totals.DistinctExecutables,
		},
		Connections: toConnections(in.Result.Connections),
		Rollups: Rollups{
			ByExecutable: toByExecutable(in.Result.ByExecutable),
			ByHost:       toByHost(in.Result.ByHost),
			ByDirection: ByDirection{
				In:  toDirection(in.Result.ByDirection.In),
				Out: toDirection(in.Result.ByDirection.Out),
			},
			Denied: toConnections(in.Result.Denied),
		},
		SkippedRows: nonNil(in.Skipped),
	}
	return doc
}

// Encode writes the document as deterministic, indented JSON with a trailing
// newline. HTML escaping is disabled so executable paths and hostnames are verbatim.
func Encode(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func toConnections(cs []aggregate.Connection) []Connection {
	out := make([]Connection, 0, len(cs))
	for _, c := range cs {
		out = append(out, Connection{
			Direction:            c.Direction,
			UID:                  c.UID,
			IPAddress:            c.IPAddress,
			RemoteHostname:       c.RemoteHostname,
			HostnameKnown:        c.RemoteHostname != "",
			Protocol:             c.Protocol,
			ProtocolName:         parse.ProtocolName(c.Protocol),
			Port:                 c.Port,
			ConnectingExecutable: c.ConnectingExecutable,
			ParentAppExecutable:  c.ParentAppExecutable,
			ConnectCount:         c.ConnectCount,
			DenyCount:            c.DenyCount,
			ByteCountIn:          c.ByteCountIn,
			ByteCountOut:         c.ByteCountOut,
			FirstSeen:            rfc3339(c.FirstSeen),
			LastSeen:             rfc3339(c.LastSeen),
		})
	}
	return out
}

func toByExecutable(es []aggregate.ByExecutable) []ByExecutable {
	out := make([]ByExecutable, 0, len(es))
	for _, e := range es {
		out = append(out, ByExecutable{
			ConnectingExecutable: e.ConnectingExecutable,
			ParentAppExecutable:  e.ParentAppExecutable,
			ByteCountIn:          e.ByteCountIn,
			ByteCountOut:         e.ByteCountOut,
			ConnectCount:         e.ConnectCount,
			DenyCount:            e.DenyCount,
			DistinctHosts:        e.DistinctHosts,
			DistinctConnections:  e.DistinctConnections,
		})
	}
	return out
}

func toByHost(hs []aggregate.ByHost) []ByHost {
	out := make([]ByHost, 0, len(hs))
	for _, h := range hs {
		out = append(out, ByHost{
			Host:                h.Host,
			HostnameKnown:       h.HostnameKnown,
			ByteCountIn:         h.ByteCountIn,
			ByteCountOut:        h.ByteCountOut,
			ConnectCount:        h.ConnectCount,
			DenyCount:           h.DenyCount,
			DistinctExecutables: h.DistinctExecutables,
		})
	}
	return out
}

func toDirection(d aggregate.DirectionAgg) DirectionAgg {
	return DirectionAgg{
		ByteCountIn:         d.ByteCountIn,
		ByteCountOut:        d.ByteCountOut,
		ConnectCount:        d.ConnectCount,
		DenyCount:           d.DenyCount,
		DistinctConnections: d.DistinctConnections,
	}
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func ptrTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := rfc3339(*t)
	return &s
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
