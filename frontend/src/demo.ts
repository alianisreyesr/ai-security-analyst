const BASE_TIME = "2026-09-22T12:00:00Z";

function at(seconds: number): string {
  const start = new Date(BASE_TIME).getTime();
  return new Date(start + seconds * 1000).toISOString();
}

export const demoEvents = [
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
    },
  })),
];

export const demoJson = JSON.stringify(demoEvents, null, 2);
