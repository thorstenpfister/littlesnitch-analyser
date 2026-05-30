// Command littlesnitch-analyser is an unprivileged stdin→stdout filter that reads
// the CSV produced by `littlesnitch log-traffic` and emits aggregated network-usage
// statistics as JSON (or a human-readable table with --human).
package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thorstenpfister/littlesnitch-analyser/internal/aggregate"
	"github.com/thorstenpfister/littlesnitch-analyser/internal/filter"
	"github.com/thorstenpfister/littlesnitch-analyser/internal/output"
	"github.com/thorstenpfister/littlesnitch-analyser/internal/parse"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:], time.Now))
}

// intList and stringList back the repeatable filter flags.
type intList []int

func (l *intList) String() string {
	parts := make([]string, len(*l))
	for i, v := range *l {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func (l *intList) Set(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer %q", s)
	}
	*l = append(*l, v)
	return nil
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(s string) error {
	*l = append(*l, s)
	return nil
}

// run is the testable entry point. It returns the process exit code.
func run(stdin io.Reader, stdout, stderr io.Writer, args []string, now func() time.Time) int {
	fs := flag.NewFlagSet("littlesnitch-analyser", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}

	var uids intList
	var connExes stringList
	var parentExes stringList
	fs.Var(&uids, "uid", "inclusion filter on uid (repeatable; OR within)")
	fs.Var(&connExes, "connecting-executable", "inclusion filter on connectingExecutable, exact match (repeatable)")
	fs.Var(&parentExes, "parent-executable", "inclusion filter on parentAppExecutable, exact match (repeatable)")
	sortFlag := fs.String("sort", "bytes", "sort key for connections: bytes|connects|denies")
	human := fs.Bool("human", false, "render a human-readable table instead of JSON")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeUsage(stdout, fs)
			return 0
		}
		writeUsage(stderr, fs)
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "littlesnitch-analyser %s\n", version)
		return 0
	}

	sortKey, ok := parseSortKey(*sortFlag)
	if !ok {
		fmt.Fprintf(stderr, "error: invalid --sort %q (want bytes|connects|denies)\n", *sortFlag)
		return 2
	}

	if isTerminal(stdin) {
		fmt.Fprintln(stderr, "error: stdin is a terminal; pipe `littlesnitch log-traffic` output into this tool")
		writeUsage(stderr, fs)
		return 2
	}

	reader := csv.NewReader(bufio.NewReaderSize(stdin, 1<<20))
	reader.FieldsPerRecord = -1

	headerRec, err := reader.Read()
	if err != nil {
		fmt.Fprintln(stderr, "error: no header received (upstream collector likely failed)")
		return 3
	}
	header, err := parse.NewHeader(headerRec)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	flt := filter.Filters{
		UIDs:                  uids,
		ConnectingExecutables: connExes,
		ParentExecutables:     parentExes,
	}

	agg := aggregate.New()
	var skipped []output.SkippedRow
	var rowsTotal, rowsMatched, rowsParsed int
	var firstDate, lastDate *time.Time

	for {
		rec, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			var pe *csv.ParseError
			if errors.As(readErr, &pe) {
				rowsTotal++
				skipped = append(skipped, output.SkippedRow{
					Line:  pe.Line,
					Raw:   strings.Join(rec, ","),
					Error: pe.Error(),
				})
				continue
			}
			fmt.Fprintf(stderr, "error: reading input: %v\n", readErr)
			return 1
		}

		rowsTotal++
		keys, err := header.DecodeKeys(rec)
		if err != nil {
			skipped = append(skipped, skipRow(reader, rec, err))
			continue
		}
		updateWindow(&firstDate, &lastDate, keys.Date)

		if !flt.Match(keys.UID, keys.ConnectingExecutable, keys.ParentAppExecutable) {
			continue
		}
		rowsMatched++

		row, err := header.DecodeRow(rec, keys)
		if err != nil {
			skipped = append(skipped, skipRow(reader, rec, err))
			continue
		}
		agg.Add(row)
		rowsParsed++
	}

	doc := output.Build(output.BuildInput{
		ToolVersion:  version,
		GeneratedAt:  now(),
		FirstRowDate: firstDate,
		LastRowDate:  lastDate,
		Filters: output.Filters{
			UID:                  uids,
			ConnectingExecutable: connExes,
			ParentExecutable:     parentExes,
		},
		CSVColumns:  header.Columns,
		RowsTotal:   rowsTotal,
		RowsMatched: rowsMatched,
		RowsParsed:  rowsParsed,
		RowsSkipped: len(skipped),
		Result:      agg.Result(sortKey),
		Skipped:     skipped,
	})

	if *human {
		if err := output.WriteHuman(stdout, doc, sortKey); err != nil {
			fmt.Fprintf(stderr, "error: writing output: %v\n", err)
			return 1
		}
		return 0
	}
	if err := output.Encode(stdout, doc); err != nil {
		fmt.Fprintf(stderr, "error: writing output: %v\n", err)
		return 1
	}
	return 0
}

func parseSortKey(s string) (aggregate.SortKey, bool) {
	switch aggregate.SortKey(s) {
	case aggregate.SortBytes, aggregate.SortConnects, aggregate.SortDenies:
		return aggregate.SortKey(s), true
	default:
		return "", false
	}
}

func skipRow(reader *csv.Reader, rec []string, err error) output.SkippedRow {
	line, _ := reader.FieldPos(0)
	return output.SkippedRow{
		Line:  line,
		Raw:   strings.Join(rec, ","),
		Error: err.Error(),
	}
}

func updateWindow(first, last **time.Time, t time.Time) {
	if *first == nil || t.Before(**first) {
		v := t
		*first = &v
	}
	if *last == nil || t.After(**last) {
		v := t
		*last = &v
	}
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func writeUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage: littlesnitch-analyser [flags]\n\n")
	fmt.Fprintf(w, "Reads `littlesnitch log-traffic` CSV on stdin and writes aggregated\n")
	fmt.Fprintf(w, "network-usage statistics as a single JSON object on stdout.\n\n")
	fmt.Fprintf(w, "Flags:\n")
	old := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(old)
}
