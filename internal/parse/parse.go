// Package parse turns the Little Snitch log-traffic CSV into typed rows. It maps
// columns by name (never by position) and decodes in two stages so the caller can
// apply filters between them and account for matched-vs-parsed rows precisely.
package parse

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RequiredColumns names every column the analyser depends on; missing any one is fatal.
var RequiredColumns = []string{
	"date", "direction", "uid", "ipAddress", "remoteHostname",
	"protocol", "port", "connectCount", "denyCount",
	"byteCountIn", "byteCountOut", "connectingExecutable", "parentAppExecutable",
}

// Header resolves the canonical column set to record indexes once at header time so
// per-row decode never re-hits the name→index map.
type Header struct {
	cols    colIdx
	Columns []string
}

type colIdx struct {
	date, direction, uid, ipAddress, remoteHostname,
	protocol, port, connectCount, denyCount,
	byteCountIn, byteCountOut, connectingExecutable, parentAppExecutable int
}

// MissingColumnsError reports required header columns that were absent.
type MissingColumnsError struct{ Missing []string }

func (e *MissingColumnsError) Error() string {
	return "missing required column(s): " + strings.Join(e.Missing, ", ")
}

// NewHeader validates that every required column is present and captures their indexes.
func NewHeader(record []string) (*Header, error) {
	idx := make(map[string]int, len(record))
	for i, name := range record {
		if _, dup := idx[name]; !dup {
			idx[name] = i
		}
	}
	var missing []string
	for _, c := range RequiredColumns {
		if _, ok := idx[c]; !ok {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return nil, &MissingColumnsError{Missing: missing}
	}
	cols := make([]string, len(record))
	copy(cols, record)
	return &Header{
		cols: colIdx{
			date:                 idx["date"],
			direction:            idx["direction"],
			uid:                  idx["uid"],
			ipAddress:            idx["ipAddress"],
			remoteHostname:       idx["remoteHostname"],
			protocol:             idx["protocol"],
			port:                 idx["port"],
			connectCount:         idx["connectCount"],
			denyCount:            idx["denyCount"],
			byteCountIn:          idx["byteCountIn"],
			byteCountOut:         idx["byteCountOut"],
			connectingExecutable: idx["connectingExecutable"],
			parentAppExecutable:  idx["parentAppExecutable"],
		},
		Columns: cols,
	}, nil
}

func field(record []string, i int) string {
	if i < len(record) {
		return record[i]
	}
	return ""
}

// Row is a fully decoded data row.
type Row struct {
	Date                 time.Time
	Direction            string
	UID                  int
	IPAddress            string
	RemoteHostname       string
	Protocol             int
	Port                 int
	ConnectCount         int64
	DenyCount            int64
	ByteCountIn          int64
	ByteCountOut         int64
	ConnectingExecutable string
	ParentAppExecutable  string
}

// Keys is the pre-filter subset of a row: the date (for the observed window) and the
// three filter inputs.
type Keys struct {
	Date                 time.Time
	UID                  int
	ConnectingExecutable string
	ParentAppExecutable  string
}

// DecodeKeys parses only what filtering needs; a failure here skips the row before
// it can be matched against filters.
func (h *Header) DecodeKeys(record []string) (Keys, error) {
	d, err := time.Parse(time.RFC3339, field(record, h.cols.date))
	if err != nil {
		return Keys{}, fmt.Errorf("date: %w", err)
	}
	uid, err := strconv.Atoi(field(record, h.cols.uid))
	if err != nil {
		return Keys{}, fmt.Errorf("uid: %w", err)
	}
	return Keys{
		Date:                 d.UTC(),
		UID:                  uid,
		ConnectingExecutable: field(record, h.cols.connectingExecutable),
		ParentAppExecutable:  field(record, h.cols.parentAppExecutable),
	}, nil
}

// DecodeRow completes a Row once filters have passed. A failure here marks a
// matched row as skipped rather than aggregated.
func (h *Header) DecodeRow(record []string, k Keys) (Row, error) {
	proto, err := strconv.Atoi(field(record, h.cols.protocol))
	if err != nil {
		return Row{}, fmt.Errorf("protocol: %w", err)
	}
	port, err := strconv.Atoi(field(record, h.cols.port))
	if err != nil {
		return Row{}, fmt.Errorf("port: %w", err)
	}
	connectCount, err := strconv.ParseInt(field(record, h.cols.connectCount), 10, 64)
	if err != nil {
		return Row{}, fmt.Errorf("connectCount: %w", err)
	}
	denyCount, err := strconv.ParseInt(field(record, h.cols.denyCount), 10, 64)
	if err != nil {
		return Row{}, fmt.Errorf("denyCount: %w", err)
	}
	byteIn, err := strconv.ParseInt(field(record, h.cols.byteCountIn), 10, 64)
	if err != nil {
		return Row{}, fmt.Errorf("byteCountIn: %w", err)
	}
	byteOut, err := strconv.ParseInt(field(record, h.cols.byteCountOut), 10, 64)
	if err != nil {
		return Row{}, fmt.Errorf("byteCountOut: %w", err)
	}
	return Row{
		Date:                 k.Date,
		Direction:            field(record, h.cols.direction),
		UID:                  k.UID,
		IPAddress:            field(record, h.cols.ipAddress),
		RemoteHostname:       field(record, h.cols.remoteHostname),
		Protocol:             proto,
		Port:                 port,
		ConnectCount:         connectCount,
		DenyCount:            denyCount,
		ByteCountIn:          byteIn,
		ByteCountOut:         byteOut,
		ConnectingExecutable: k.ConnectingExecutable,
		ParentAppExecutable:  k.ParentAppExecutable,
	}, nil
}

// ProtocolName maps an IP protocol number to a short name, falling back to
// "proto-<n>" for values not named explicitly.
func ProtocolName(n int) string {
	switch n {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return "proto-" + strconv.Itoa(n)
	}
}
