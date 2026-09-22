# Ingestion and Normalization

v0.2 accepts canonical structured events and three initial log families.

## Pipeline

```mermaid
flowchart LR
    A["Raw Input"] --> B{"Format"}
    B --> C["SSH/Auth Parser"]
    B --> D["Web Access Parser"]
    B --> E["Firewall Parser"]
    B --> F["CSV / JSON Validator"]
    C --> G["Canonical Event"]
    D --> G
    E --> G
    F --> G
    G --> H[("security_events")]

    classDef raw fill:#0f172a,stroke:#38bdf8,color:#f8fafc,stroke-width:2px;
    classDef parser fill:#172554,stroke:#60a5fa,color:#eff6ff,stroke-width:2px;
    classDef event fill:#3b0764,stroke:#c084fc,color:#faf5ff,stroke-width:2px;
    classDef data fill:#052e16,stroke:#4ade80,color:#f0fdf4,stroke-width:2px;

    class A,B raw;
    class C,D,E,F parser;
    class G event;
    class H data;
```

## Parser contract

Every parser implements `LogParser.parse_line(line)` and returns either:
- a validated `SecurityEventCreate`, or
- `None` when the line is unsupported/malformed.

The dispatcher tries supported parsers in a deterministic order. Parser failures do not include the raw line in user-facing error messages.

## Linux SSH/Auth

Supported initial patterns:
- `Failed password for <user> from <ip>`
- `Failed password for invalid user <user> from <ip>`
- `Accepted <method> for <user> from <ip>`

Syslog timestamps use the configured/runtime year because traditional auth.log lines omit the year.

## Apache/Nginx

The initial web parser supports common/combined-style access records where the request starts with:

`IP - - [timestamp] "METHOD PATH HTTP/x.x" STATUS SIZE`

The same normalized parser works for Apache and Nginx when they emit this compatible layout.

## Generic firewall format

The initial documented format is whitespace-separated `KEY=VALUE` data:

`TIMESTAMP=... SRC=... DST=... SPT=... DPT=... PROTO=... ACTION=...`

Required keys:
- `TIMESTAMP`
- `SRC`
- `DST`

Unknown extra keys are ignored.

## Batch API

`POST /api/v1/ingest/batch`

Supported format values:
- `json`
- `csv`
- `log`
- `txt`

Limits are configurable using:
- `MAX_BATCH_ROWS`
- `MAX_BATCH_CONTENT_CHARS`

Partial parsing errors return line/row context without echoing sensitive input content.

## Duplicate strategy

v0.2 deliberately does **not** silently deduplicate raw security events because two identical-looking log records can represent distinct observations. Each accepted row receives its own event ID.

Threat-level duplicate creation is prevented separately using a deterministic SHA-256 fingerprint of the rule, source, time range and supporting event IDs.

Future event-level deduplication, if needed for a specific source, should use source-specific stable identifiers rather than deleting repeated-looking telemetry globally.
