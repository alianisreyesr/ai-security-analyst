# Threat Intelligence and MITRE ATT&CK

v0.4 enriches deterministic threats without making enrichment a dependency of ingestion or detection.

## Enrichment flow

```mermaid
flowchart LR
    A[("Threat")] --> B["MITRE Mapping"]
    A --> C{"Source IP global?"}
    C -- "No" --> D["Skip External Reputation"]
    C -- "Yes" --> E{"Fresh Cache?"}
    E -- "Yes" --> F["Cached Reputation"]
    E -- "No" --> G["Optional Provider"]
    G -- "Success" --> H["Cache Result"]
    G -- "Failure" --> I["Unavailable Status"]
    B --> J["Threat Detail"]
    D --> J
    F --> J
    H --> J
    I --> J

    classDef data fill:#052e16,stroke:#4ade80,color:#f0fdf4,stroke-width:2px;
    classDef decision fill:#422006,stroke:#facc15,color:#fefce8,stroke-width:2px;
    classDef intel fill:#172554,stroke:#60a5fa,color:#eff6ff,stroke-width:2px;
    classDef safe fill:#450a0a,stroke:#f87171,color:#fef2f2,stroke-width:2px;

    class A,H data;
    class C,E decision;
    class B,F,G,J intel;
    class D,I safe;
```

## MITRE mappings

Mappings are tied to deterministic rule IDs and are absent when evidence is insufficient.

| Detection rule | Technique | Tactic |
|---|---|---|
| `auth.brute_force` | T1110 — Brute Force | Credential Access |
| `auth.brute_force_success` | T1110 — Brute Force | Credential Access |
| `network.port_scan` | T1046 — Network Service Discovery | Discovery |

`web.request_burst` intentionally has no ATT&CK mapping in v0.4 because request volume alone is not enough to assert a specific technique.

## IP reputation

The default provider is `disabled`. External lookups are optional.

Controls:
- Non-global/private/local addresses never trigger external lookups.
- Provider timeouts/errors return `unavailable`; they do not interrupt ingestion.
- Successful results are cached.
- Cache TTL is configurable.
- Provider credentials remain environment configuration.
- Raw provider responses are not persisted; only validated verdict/score/details are stored.

## Threat exploration

Available APIs:
- Threat list with severity, source-IP, rule, free-text and date filters
- Pagination with `limit` and `offset`
- Chronological evidence timeline
- Source-IP aggregate statistics
- MITRE mappings attached to threat-list items

Timeline timestamps are returned as UTC-aware values.
