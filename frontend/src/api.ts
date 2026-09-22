import type {
  AnalysisRunResponse,
  BatchIngestResponse,
  EventListResponse,
  HealthResponse,
  SourceStatisticsResponse,
  ThreatListResponse,
  ThreatTimelineResponse,
} from "./types";

const API_KEY_STORAGE = "ai-security-analyst-api-key";

export function getApiKey(): string {
  return localStorage.getItem(API_KEY_STORAGE) ?? "";
}

export function setApiKey(value: string): void {
  if (value.trim()) {
    localStorage.setItem(API_KEY_STORAGE, value.trim());
  } else {
    localStorage.removeItem(API_KEY_STORAGE);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const apiKey = getApiKey();

  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (apiKey) {
    headers.set("X-API-Key", apiKey);
  }

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {
      // Keep status text if the body is not JSON.
    }
    throw new Error(`${response.status} ${detail}`);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<HealthResponse>("/health"),
  events: (limit = 50) =>
    request<EventListResponse>(`/api/v1/events?limit=${limit}`),
  threats: (limit = 50) =>
    request<ThreatListResponse>(`/api/v1/threats?limit=${limit}`),
  sourceStatistics: () =>
    request<SourceStatisticsResponse>("/api/v1/threats/sources/statistics?limit=8"),
  threatTimeline: (id: number) =>
    request<ThreatTimelineResponse>(`/api/v1/threats/${id}/timeline?limit=200`),
  ingest: (format: "json" | "csv" | "log" | "txt", content: string) =>
    request<BatchIngestResponse>("/api/v1/ingest/batch", {
      method: "POST",
      body: JSON.stringify({ format, content }),
    }),
  analyze: () =>
    request<AnalysisRunResponse>("/api/v1/analysis/run", {
      method: "POST",
      body: JSON.stringify({ limit: 5000 }),
    }),
};
