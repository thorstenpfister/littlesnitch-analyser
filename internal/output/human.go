package output

import (
	"bufio"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/thorstenpfister/littlesnitch-analyser/internal/aggregate"
)

// WriteHuman renders a compact, deterministic fixed-width table. The connection
// list is complete (never truncated) and already ordered per the active sort. JSON
// remains the canonical output; this is for a human eyeballing a run.
func WriteHuman(w io.Writer, doc Document, sort aggregate.SortKey) error {
	bw := bufio.NewWriter(w)

	fmt.Fprintf(bw, "%s %s\n", doc.Meta.Tool, doc.Meta.ToolVersion)
	fmt.Fprintf(bw, "window: %s .. %s\n", orDash(doc.Meta.ObservedWindow.FirstRowDate), orDash(doc.Meta.ObservedWindow.LastRowDate))
	fmt.Fprintf(bw, "rows: total=%d matched=%d parsed=%d skipped=%d\n",
		doc.Meta.RowsTotal, doc.Meta.RowsMatchedFilter, doc.Meta.RowsParsed, doc.Meta.RowsSkipped)
	t := doc.Totals
	fmt.Fprintf(bw, "totals: bytesIn=%d bytesOut=%d connects=%d denies=%d (connections=%d hosts=%d executables=%d)\n\n",
		t.ByteCountIn, t.ByteCountOut, t.ConnectCount, t.DenyCount,
		t.DistinctConnections, t.DistinctHosts, t.DistinctExecutables)

	fmt.Fprintf(bw, "CONNECTIONS (sort=%s):\n", sort)
	writeConnTable(bw, doc.Connections)

	if len(doc.Rollups.Denied) > 0 {
		fmt.Fprint(bw, "\nDENIED:\n")
		writeConnTable(bw, doc.Rollups.Denied)
	}

	return bw.Flush()
}

func writeConnTable(w io.Writer, conns []Connection) {
	if len(conns) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DIR\tUID\tPROTO\tPORT\tHOST\tIN\tOUT\tCONN\tDENY\tEXECUTABLE")
	for _, c := range conns {
		host := c.RemoteHostname
		if host == "" {
			host = c.IPAddress
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\n",
			c.Direction, c.UID, c.ProtocolName, c.Port, host,
			c.ByteCountIn, c.ByteCountOut, c.ConnectCount, c.DenyCount, c.ConnectingExecutable)
	}
	tw.Flush()
}

func orDash(s *string) string {
	if s == nil {
		return "—"
	}
	return *s
}
