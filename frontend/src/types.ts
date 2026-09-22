export type Severity = "low" | "medium" | "high" | "critical" | string;

export interface HealthResponse {
  status: "healthy";
}

export interface EventItem {
  id: number;
  timestamp: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  event_type: string;
  username: string | null;
  source: string;
  created_at: string;
}

export interface EventListResponse {
  total: number;
  limit: number;
  offset: number;
  items: EventItem[];
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
}

export interface ThreatItem {
  id: number;
  rule_id: string;
  title: string;
  source_ip: string | null;
  risk_score: number;
  severity: Severity;
  first_seen: string;
  last_seen: string;
  event_count: number;
  mitre: MitreTechnique[];
}

export interface ThreatListResponse {
  total: number;
  limit: number;
  offset: number;
  items: ThreatItem[];
}

export interface TimelineEvent {
  id: number;
  timestamp: string;
  event_type: string;
  source: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  username: string | null;
}

export interface ThreatTimelineResponse {
  threat_id: number;
  rule_id: string;
  total: number;
  limit: number;
  offset: number;
  events: TimelineEvent[];
}

export interface SourceStatistic {
  source_ip: string;
  threat_count: number;
  max_risk_score: number;
  last_seen: string;
}

export interface SourceStatisticsResponse {
  items: SourceStatistic[];
}

export interface BatchIngestResponse {
  accepted: number;
  rejected: number;
  event_ids: number[];
  errors: string[];
}

export interface AnalysisRunResponse {
  analyzed_event_limit: number;
  threats: Array<{
    id: number;
    rule_id: string;
    title: string;
    source_ip: string | null;
    risk_score: number;
    severity: string;
    event_ids: number[];
    evidence: Record<string, unknown>;
  }>;
}
