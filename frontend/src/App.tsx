import { useCallback, useEffect, useMemo, useState } from "react";

import { api, getApiKey, setApiKey } from "./api";
import { demoJson } from "./demo";
import type {
  EventItem,
  SourceStatistic,
  ThreatItem,
  ThreatTimelineResponse,
} from "./types";

type View = "overview" | "events" | "threats" | "ingestion";

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function severityClass(value: string): string {
  return `severity severity-${value.toLowerCase()}`;
}

function App() {
  const [view, setView] = useState<View>("overview");
  const [events, setEvents] = useState<EventItem[]>([]);
  const [eventTotal, setEventTotal] = useState(0);
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [threatTotal, setThreatTotal] = useState(0);
  const [sources, setSources] = useState<SourceStatistic[]>([]);
  const [apiHealthy, setApiHealthy] = useState<boolean | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatItem | null>(null);
  const [timeline, setTimeline] = useState<ThreatTimelineResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState("");
  const [error, setError] = useState("");
  const [apiKey, setApiKeyState] = useState(getApiKey());
  const [format, setFormat] = useState<"json" | "csv" | "log" | "txt">("json");
  const [ingestContent, setIngestContent] = useState(demoJson);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [health, eventData, threatData, sourceData] = await Promise.all([
        api.health(),
        api.events(100),
        api.threats(100),
        api.sourceStatistics(),
      ]);
      setApiHealthy(health.status === "healthy");
      setEvents(eventData.items);
      setEventTotal(eventData.total);
      setThreats(threatData.items);
      setThreatTotal(threatData.total);
      setSources(sourceData.items);
    } catch (err) {
      setApiHealthy(false);
      setError(err instanceof Error ? err.message : "Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const criticalCount = useMemo(
    () => threats.filter((item) => item.severity.toLowerCase() === "critical").length,
    [threats],
  );

  const highCount = useMemo(
    () => threats.filter((item) => item.severity.toLowerCase() === "high").length,
    [threats],
  );

  async function loadThreat(threat: ThreatItem) {
    setSelectedThreat(threat);
    setTimeline(null);
    setError("");
    try {
      setTimeline(await api.threatTimeline(threat.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load threat timeline.");
    }
  }

  async function runDemo() {
    setLoading(true);
    setError("");
    setActionMessage("");
    try {
      const ingested = await api.ingest("json", demoJson);
      const analyzed = await api.analyze();
      setActionMessage(
        `Demo loaded: ${ingested.accepted} events accepted, ${analyzed.threats.length} threats detected.`,
      );
      await refresh();
      setView("overview");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Demo workflow failed.");
    } finally {
      setLoading(false);
    }
  }

  async function ingestCustom() {
    setLoading(true);
    setError("");
    setActionMessage("");
    try {
      const result = await api.ingest(format, ingestContent);
      setActionMessage(
        `Ingestion complete: ${result.accepted} accepted, ${result.rejected} rejected.`,
      );
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ingestion failed.");
    } finally {
      setLoading(false);
    }
  }

  async function analyzeNow() {
    setLoading(true);
    setError("");
    setActionMessage("");
    try {
      const result = await api.analyze();
      setActionMessage(`Analysis complete: ${result.threats.length} threats detected.`);
      await refresh();
      setView("threats");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  function saveApiKey() {
    setApiKey(apiKey);
    setActionMessage(apiKey.trim() ? "API key saved locally." : "API key cleared.");
    void refresh();
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <div className="brand-mark">ASA</div>
          <div className="brand-copy">
            <strong>AI Security Analyst</strong>
            <span>Explainable threat analysis</span>
          </div>
        </div>

        <nav>
          {(["overview", "events", "threats", "ingestion"] as View[]).map((item) => (
            <button
              key={item}
              className={view === item ? "nav-item active" : "nav-item"}
              onClick={() => setView(item)}
            >
              {item[0].toUpperCase() + item.slice(1)}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="status-row">
            <span className={apiHealthy ? "status-dot online" : "status-dot"} />
            <span>{apiHealthy ? "API online" : "API unavailable"}</span>
          </div>
          <button className="secondary-button full" onClick={() => void refresh()}>
            Refresh data
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Security Operations</p>
            <h1>{view[0].toUpperCase() + view.slice(1)}</h1>
          </div>
          <div className="topbar-actions">
            <button className="secondary-button" onClick={() => void analyzeNow()} disabled={loading}>
              Run analysis
            </button>
            <button className="primary-button" onClick={() => void runDemo()} disabled={loading}>
              Load demo + analyze
            </button>
          </div>
        </header>

        {error && <div className="notice error">{error}</div>}
        {actionMessage && <div className="notice success">{actionMessage}</div>}

        {view === "overview" && (
          <>
            <section className="metric-grid">
              <Metric label="Security events" value={eventTotal} subtext="Normalized events stored" />
              <Metric label="Detected threats" value={threatTotal} subtext="Deterministic detections" />
              <Metric label="Critical" value={criticalCount} subtext="Visible in latest 100" />
              <Metric label="High" value={highCount} subtext="Visible in latest 100" />
            </section>

            <section className="two-column">
              <div className="panel">
                <PanelHeader title="Recent threats" action="View all" onAction={() => setView("threats")} />
                {threats.length === 0 ? (
                  <EmptyState
                    title="No threats yet"
                    detail="Load the demo scenario or ingest events, then run analysis."
                  />
                ) : (
                  <div className="list-stack">
                    {threats.slice(0, 6).map((threat) => (
                      <button
                        className="threat-row"
                        key={threat.id}
                        onClick={() => void loadThreat(threat)}
                      >
                        <div>
                          <strong>{threat.title}</strong>
                          <span>{threat.source_ip ?? "Unknown source"} · {threat.rule_id}</span>
                        </div>
                        <div className="threat-score">
                          <span className={severityClass(threat.severity)}>{threat.severity}</span>
                          <strong>{threat.risk_score}</strong>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="panel">
                <PanelHeader title="Top source IPs" />
                {sources.length === 0 ? (
                  <EmptyState title="No source statistics" detail="Threat source statistics will appear here." />
                ) : (
                  <div className="list-stack">
                    {sources.map((source) => (
                      <div className="source-row" key={source.source_ip}>
                        <div>
                          <strong>{source.source_ip}</strong>
                          <span>{source.threat_count} threats</span>
                        </div>
                        <div className="risk-bar-wrap">
                          <div className="risk-bar">
                            <span style={{ width: `${source.max_risk_score}%` }} />
                          </div>
                          <strong>{source.max_risk_score}</strong>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>

            <section className="panel">
              <PanelHeader title="Recent events" action="View all" onAction={() => setView("events")} />
              <EventTable events={events.slice(0, 8)} />
            </section>
          </>
        )}

        {view === "events" && (
          <section className="panel">
            <PanelHeader title={`Events (${eventTotal})`} />
            <EventTable events={events} />
          </section>
        )}

        {view === "threats" && (
          <section className="panel">
            <PanelHeader title={`Threats (${threatTotal})`} />
            {threats.length === 0 ? (
              <EmptyState
                title="No threats detected"
                detail="Ingest a demo scenario and run the deterministic detection engine."
              />
            ) : (
              <div className="threat-table">
                {threats.map((threat) => (
                  <button
                    className="threat-card"
                    key={threat.id}
                    onClick={() => void loadThreat(threat)}
                  >
                    <div>
                      <span className={severityClass(threat.severity)}>{threat.severity}</span>
                      <h3>{threat.title}</h3>
                      <p>{threat.source_ip ?? "Unknown source"} · {threat.rule_id}</p>
                    </div>
                    <div className="threat-card-meta">
                      <strong>{threat.risk_score}/100</strong>
                      <span>{threat.event_count} events</span>
                      <span>{threat.mitre.map((item) => item.technique_id).join(", ") || "No MITRE map"}</span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </section>
        )}

        {view === "ingestion" && (
          <section className="ingestion-layout">
            <div className="panel">
              <PanelHeader title="Batch ingestion" />
              <label className="field-label" htmlFor="format">Format</label>
              <select
                id="format"
                value={format}
                onChange={(event) => setFormat(event.target.value as typeof format)}
              >
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
                <option value="log">LOG</option>
                <option value="txt">TXT</option>
              </select>

              <label className="field-label" htmlFor="ingest-content">Content</label>
              <textarea
                id="ingest-content"
                value={ingestContent}
                onChange={(event) => setIngestContent(event.target.value)}
                spellCheck={false}
              />

              <div className="button-row">
                <button className="primary-button" onClick={() => void ingestCustom()} disabled={loading}>
                  Ingest events
                </button>
                <button className="secondary-button" onClick={() => setIngestContent(demoJson)}>
                  Restore demo JSON
                </button>
              </div>
            </div>

            <div className="panel">
              <PanelHeader title="API access" />
              <p className="muted">
                Local development runs with authentication disabled. If you enable API-key auth,
                save the analyst/admin key here; it stays in this browser only.
              </p>
              <label className="field-label" htmlFor="api-key">X-API-Key</label>
              <input
                id="api-key"
                type="password"
                value={apiKey}
                onChange={(event) => setApiKeyState(event.target.value)}
                placeholder="Optional in local development"
              />
              <div className="button-row">
                <button className="secondary-button" onClick={saveApiKey}>Save key</button>
              </div>
            </div>
          </section>
        )}

        {loading && <div className="loading-bar" aria-label="Loading" />}
      </main>

      {selectedThreat && (
        <div className="drawer-backdrop" onClick={() => setSelectedThreat(null)}>
          <aside className="drawer" onClick={(event) => event.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <span className={severityClass(selectedThreat.severity)}>{selectedThreat.severity}</span>
                <h2>{selectedThreat.title}</h2>
                <p>{selectedThreat.rule_id}</p>
              </div>
              <button className="icon-button" onClick={() => setSelectedThreat(null)}>×</button>
            </div>

            <div className="drawer-metrics">
              <Metric label="Risk" value={selectedThreat.risk_score} subtext="out of 100" />
              <Metric label="Events" value={selectedThreat.event_count} subtext="supporting evidence" />
            </div>

            <h3>MITRE ATT&CK</h3>
            <div className="tag-list">
              {selectedThreat.mitre.length ? selectedThreat.mitre.map((item) => (
                <span className="tag" key={item.technique_id}>
                  {item.technique_id} · {item.name}
                </span>
              )) : <span className="muted">No mapping for this rule.</span>}
            </div>

            <h3>Evidence timeline</h3>
            {!timeline ? (
              <p className="muted">Loading timeline…</p>
            ) : timeline.events.length === 0 ? (
              <p className="muted">No supporting events found.</p>
            ) : (
              <div className="timeline">
                {timeline.events.map((event) => (
                  <div className="timeline-item" key={event.id}>
                    <span />
                    <div>
                      <strong>{event.event_type}</strong>
                      <p>{formatTime(event.timestamp)}</p>
                      <small>
                        {event.source_ip ?? "?"} → {event.destination_ip ?? "?"}
                        {event.destination_port ? `:${event.destination_port}` : ""}
                      </small>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  subtext,
}: {
  label: string;
  value: number;
  subtext: string;
}) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{subtext}</small>
    </article>
  );
}

function PanelHeader({
  title,
  action,
  onAction,
}: {
  title: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <div className="panel-header">
      <h2>{title}</h2>
      {action && onAction && (
        <button className="text-button" onClick={onAction}>{action}</button>
      )}
    </div>
  );
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

function EventTable({ events }: { events: EventItem[] }) {
  if (events.length === 0) {
    return <EmptyState title="No events yet" detail="Ingest data to populate the event stream." />;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Origin</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{formatTime(event.timestamp)}</td>
              <td><span className="event-pill">{event.event_type}</span></td>
              <td>{event.source_ip ?? "—"}{event.source_port ? `:${event.source_port}` : ""}</td>
              <td>{event.destination_ip ?? "—"}{event.destination_port ? `:${event.destination_port}` : ""}</td>
              <td>{event.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
