const BASE_TIME = "2026-09-22T12:00:00Z";

function at(seconds: number): string {
  const start = new Date(BASE_TIME).getTime();
  return new Date(start + seconds * 1000).toISOString();
}

export const demoEvents = [
  {
    timestamp: "2026-09-22T11:55:00Z",
    source_ip: "192.0.2.10",
    destination_ip: "10.0.0.5",
    source_port: 51000,
    destination_port: 22,
    protocol: "TCP",
    event_type: "authentication_success",
    username: "demo-user",
    source: "linux_ssh",
    raw_payload: {
      synthetic: true,
      scenario: "normal-authentication",
    },
  },
  {
    timestamp: "2026-09-22T11:56:00Z",
    source_ip: "192.0.2.20",
    destination_ip: "10.0.0.80",
    source_port: 51001,
    destination_port: 443,
    protocol: "TCP",
    event_type: "http_request",
    username: null,
    source: "nginx",
    raw_payload: {
      synthetic: true,
      scenario: "normal-web-request",
      method: "GET",
      path: "/health",
      status: 200,
    },
  },
  {
    timestamp: "2026-09-22T11:57:00Z",
    source_ip: "192.0.2.30",
    destination_ip: "10.0.0.5",
    source_port: 51002,
    destination_port: 53,
    protocol: "UDP",
    event_type: "firewall_allow",
    username: null,
    source: "firewall",
    raw_payload: {
      synthetic: true,
      scenario: "normal-firewall-traffic",
    },
  },
  ...Array.from({ length: 6 }, (_, index) => ({
    timestamp: at(index * 20),
    source_ip: "203.0.113.42",
    destination_ip: "10.0.0.5",
    source_port: 54000 + index,
    destination_port: 22,
    protocol: "TCP",
    event_type: "authentication_failure",
    username: "admin",
    source: "linux_ssh",
    raw_payload: {
      synthetic: true,
      scenario: "brute-force-demo",
      attempt: index + 1,
    },
  })),
  ...Array.from({ length: 12 }, (_, index) => ({
    timestamp: at(300 + index * 8),
    source_ip: "198.51.100.77",
    destination_ip: "10.0.0.5",
    source_port: 55000 + index,
    destination_port: 20 + index,
    protocol: "TCP",
    event_type: "firewall_deny",
    username: null,
    source: "firewall",
    raw_payload: {
      synthetic: true,
      scenario: "port-scan-demo",
      probe: index + 1,
    },
  })),
];

export const demoJson = JSON.stringify(demoEvents, null, 2);
