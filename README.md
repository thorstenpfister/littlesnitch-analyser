# littlesnitch-analyser

An **unprivileged** command-line tool that consumes the CSV stream produced by
`littlesnitch log-traffic` (which requires `sudo`) and emits **aggregated
network-usage statistics**, by default as a single JSON object on stdout.

The privileged collector and the unprivileged analyser are separated by a pipe:

```sh
sudo littlesnitch log-traffic --begin-date "<start>" --end-date "<end>" | littlesnitch-analyser [flags]
```

## Disclaimer

This is an independent, unofficial open-source project. It is **not affiliated
with, endorsed by, or sponsored by Objective Development Software GmbH**, the
makers of [Little Snitch](https://www.obdev.at/products/littlesnitch/index-en.html).
"Little Snitch" is a trademark of Objective Development Software GmbH; all other
trademarks are the property of their respective owners. This project simply
consumes the CSV output of the `littlesnitch log-traffic` command shipped with
Little Snitch and requires a licensed installation of that product to be useful.

## Design principles

- **Full transparency.** No connection is ever dropped or summarised away. Every
  distinct flow appears in the output. Rows that fail to parse are surfaced in the
  `skipped_rows` array, never silently discarded.
- **Privilege separation.** A pure stdin → stdout filter. It never escalates, never
  shells out, never reads or writes files.
- **Determinism.** Identical input produces byte-identical output (stable sort orders,
  fixed field ordering), so runs can be diffed and golden tests are stable.

## Build

```sh
make build     # produces ./bin/littlesnitch-analyser
```

Or directly: `go build -o littlesnitch-analyser ./cmd/littlesnitch-analyser`.

## Usage

```sh
littlesnitch-analyser [flags] < traffic.csv
```

| Flag | Repeatable | Meaning |
|---|---|---|
| `--uid <int>` | yes | Inclusion filter on the `uid` column. |
| `--connecting-executable <string>` | yes | Inclusion filter on `connectingExecutable` (exact match). Isolates a process's own traffic. |
| `--parent-executable <string>` | yes | Inclusion filter on `parentAppExecutable` (exact match). App-granularity lens. |
| `--sort bytes\|connects\|denies` | no | Sort key for `connections` and rollups. Default `bytes` (= `byteCountIn + byteCountOut`). |
| `--human` | no | Render a human-readable table instead of JSON. JSON is canonical. |
| `--version` | no | Print version and exit. |
| `-h`, `--help` | no | Print usage and exit. |

**Filter semantics:** within a filter type, values OR together (`--uid 0 --uid 501`
⇒ uid ∈ {0, 501}); across types, conditions AND together. Matching is exact,
case-sensitive, full-value. Filtering is applied before aggregation, so `totals`
reflects the post-filter view.

## Input

`littlesnitch log-traffic` emits RFC-4180 CSV with the header as the first line.
The 13 columns the analyser depends on:

| Column | Type | Notes |
|---|---|---|
| `date` | RFC 3339 UTC | Start of the interval this row covers (e.g. `2026-05-29T07:00:00Z`). |
| `direction` | enum | `in` or `out`. |
| `uid` | int | |
| `ipAddress` | string | IPv4 or IPv6. |
| `remoteHostname` | string | Often empty. |
| `protocol` | int | `6`=TCP, `17`=UDP, `1`=ICMP, `58`=ICMPv6. Other values are kept and named `proto-<n>`. |
| `port` | int | Remote port for `out`, local port for `in`. |
| `connectCount`, `denyCount`, `byteCountIn`, `byteCountOut` | int64 | **Deltas** over the row's interval, not running totals — aggregation is pure summation. |
| `connectingExecutable` | string | Full path. To isolate a daemon or CLI's own traffic, filter on this (not `parentAppExecutable`). |
| `parentAppExecutable` | string | App-bundle hint; empty for standalone binaries and daemons. Populated for app-bundle helpers (e.g. `…/Signal Helper` → `…/Signal`). |

Columns are mapped **by name, not position**: a future Little Snitch version that
reorders or appends columns is handled transparently. Missing any required column
fails the run with exit code 3. Extra columns are ignored.

Rows that fail to parse (CSV `*csv.ParseError` or a non-numeric value in a numeric
field) are appended to `skipped_rows` with their line number and the raw text; the
run continues.

## Aggregation

The canonical unit is one record per distinct **flow**, keyed by the full tuple:

```
(direction, uid, ipAddress, remoteHostname, protocol, port,
 connectingExecutable, parentAppExecutable)
```

For each key the four counters sum across rows, and `firstSeen` / `lastSeen` track
the min/max row date. This per-flow map is the single source of truth; every rollup
(`by_executable`, `by_host`, `by_direction`, `denied`) is derived from it, so totals
always reconcile.

When `remoteHostname` is empty, `by_host` falls back to `ipAddress` and flags the
entry with `"hostname_known": false`.

Sort order is deterministic: primary metric desc, then the key tuple field-by-field
asc. Rollup arrays sort by their own metric desc, then by group key asc. `denied`
is always sorted by `denyCount` desc regardless of `--sort`.

## Exit codes

| Code | Condition |
|---|---|
| `0` | Success, including a valid empty window (header present, zero data rows) or all rows filtered out. |
| `2` | Usage error (bad flags, or stdin is a TTY rather than a pipe). |
| `3` | No header received (immediate EOF or a header missing required columns) — the upstream collector likely failed. No JSON is emitted. |
| `1` | Any other fatal I/O error. |

Check the upstream `sudo littlesnitch` exit status independently (via the shell
pipeline status); the analyser only sees the byte stream.

## Output schema

A single JSON object on stdout. Field order is fixed for stable diffs. All arrays
are always present; empty when there is nothing, never `null`.

```jsonc
{
  "meta": {
    "tool": "littlesnitch-analyser",
    "tool_version": "<semver>",
    "generated_at": "<RFC3339 UTC, when the tool ran>",
    "observed_window": { "first_row_date": "<RFC3339 UTC or null>", "last_row_date": "<RFC3339 UTC or null>" },
    "filters": {
      "uid": [],
      "connecting_executable": [],
      "parent_executable": []
    },
    "csv_columns": ["date", "direction", "..."],   // header as received, in order
    "rows_total": 0,             // data rows seen (excludes header)
    "rows_matched_filter": 0,
    "rows_parsed": 0,            // matched rows successfully aggregated
    "rows_skipped": 0
  },
  "totals": {                    // post-filter
    "byteCountIn": 0, "byteCountOut": 0, "connectCount": 0, "denyCount": 0,
    "distinct_connections": 0, "distinct_hosts": 0, "distinct_executables": 0
  },
  "connections": [               // COMPLETE list, no top-N, sorted per --sort
    {
      "direction": "out", "uid": 501,
      "ipAddress": "15.197.251.99", "remoteHostname": "", "hostname_known": false,
      "protocol": 6, "protocolName": "tcp", "port": 443,
      "connectingExecutable": "/path/to/exe", "parentAppExecutable": "",
      "connectCount": 0, "denyCount": 0, "byteCountIn": 0, "byteCountOut": 0,
      "firstSeen": "2026-05-29T07:00:00Z", "lastSeen": "2026-05-29T07:00:00Z"
    }
  ],
  "rollups": {
    "by_executable": [
      { "connectingExecutable": "...", "parentAppExecutable": "...",
        "byteCountIn": 0, "byteCountOut": 0, "connectCount": 0, "denyCount": 0,
        "distinct_hosts": 0, "distinct_connections": 0 }
    ],
    "by_host": [
      { "host": "15.197.251.99", "hostname_known": false,
        "byteCountIn": 0, "byteCountOut": 0, "connectCount": 0, "denyCount": 0,
        "distinct_executables": 0 }
    ],
    "by_direction": {
      "in":  { "byteCountIn": 0, "byteCountOut": 0, "connectCount": 0, "denyCount": 0, "distinct_connections": 0 },
      "out": { "byteCountIn": 0, "byteCountOut": 0, "connectCount": 0, "denyCount": 0, "distinct_connections": 0 }
    },
    "denied": [                  // every flow with denyCount > 0; duplicates entries already in `connections`
      { "...same shape as a connections entry..." }
    ]
  },
  "skipped_rows": [
    { "line": 42, "raw": "<best-effort raw or rejoined fields>", "error": "<message>" }
  ]
}
```

`--human` renders a deterministic fixed-width table to stdout instead — the full
connection list (never truncated) ordered per `--sort`, followed by a `denied`
section if any. JSON is the canonical output.

## Edge cases

- **Empty window** (header only, no rows): exit 0; valid JSON with empty arrays and
  `observed_window` dates `null`.
- **No header / immediate EOF**: exit 3, message on stderr, no JSON.
- **stdin is a TTY** (no pipe): exit 2 with a usage hint on stderr.
- **All rows filtered out**: exit 0; `rows_matched_filter: 0`, distinguishable from
  an empty window by `rows_total > 0`.
- **Duplicate flows across intervals**: sum into one entry with min/max
  `firstSeen` / `lastSeen`.
- **IPv6 addresses or hostnames containing colons**: strings throughout; no parsing
  of address structure is required.

## Development

Common tasks are wrapped in the `Makefile`; run `make help` for the full list.

```sh
make test            # run unit + golden tests
make vet             # go vet ./...
make fmt-check       # fail if any file isn't gofmt-clean
make update-golden   # regenerate golden fixtures after intended output changes
make clean           # remove ./bin
```
