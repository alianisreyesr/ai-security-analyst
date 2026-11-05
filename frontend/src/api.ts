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

// The key lives in sessionStorage so it is dropped when the tab closes and is
// never persisted to disk. Any XSS could still read it while the tab is open.
export function getApiKey(): string {
  try {
    // Remove keys persisted by earlier versions that used localStorage.
    localStorage.removeItem(API_KEY_STORAGE);
    return sessionStorage.getItem(API_KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(value: string): void {
  try {
    if (value.trim()) {
      sessionStorage.setItem(API_KEY_STORAGE, value.trim());
    } else {
      sessionStorage.removeItem(API_KEY_STORAGE);
    }
  } catch {
    // Storage may be unavailable (private mode); the key is then simply not retained.
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
