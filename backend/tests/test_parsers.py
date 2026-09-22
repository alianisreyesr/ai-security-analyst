from datetime import UTC

from app.ingestion.parsers.dispatcher import parse_log_line
from app.ingestion.parsers.firewall import FirewallParser
from app.ingestion.parsers.ssh import SSHAuthParser
from app.ingestion.parsers.web import WebAccessParser


def test_ssh_failed_login_parser() -> None:
    parser = SSHAuthParser(year=2026)
    event = parser.parse_line(
        "Sep 21 20:32:14 host sshd[123]: Failed password for invalid user admin "
        "from 203.0.113.42 port 54400 ssh2"
    )

    assert event is not None
    assert str(event.source_ip) == "203.0.113.42"
    assert event.username == "admin"
    assert event.event_type == "authentication_failure"
    assert event.timestamp.tzinfo is UTC


def test_ssh_success_parser() -> None:
    parser = SSHAuthParser(year=2026)
    event = parser.parse_line(
        "Sep 21 20:33:14 host sshd[123]: Accepted publickey for analyst "
        "from 203.0.113.42 port 54400 ssh2"
    )

    assert event is not None
    assert event.username == "analyst"
    assert event.event_type == "authentication_success"


def test_web_access_parser() -> None:
    event = WebAccessParser().parse_line(
        '203.0.113.10 - - [21/Sep/2026:20:00:00 +0000] '
        '"GET /login HTTP/1.1" 401 123 "-" "synthetic-agent"'
    )

    assert event is not None
    assert event.event_type == "http_request"
    assert event.raw_payload is not None
    assert event.raw_payload["status"] == 401
    assert event.raw_payload["path"] == "/login"


def test_firewall_parser() -> None:
    event = FirewallParser().parse_line(
        "TIMESTAMP=2026-09-21T20:00:00Z SRC=203.0.113.15 DST=10.0.0.5 "
        "SPT=50123 DPT=22 PROTO=TCP ACTION=DENY"
    )

    assert event is not None
    assert event.event_type == "firewall_deny"
    assert event.destination_port == 22
    assert event.protocol == "TCP"


def test_parsers_reject_unknown_lines() -> None:
    assert SSHAuthParser(year=2026).parse_line("not an auth log") is None
    assert WebAccessParser().parse_line("not a web access log") is None
    assert FirewallParser().parse_line("not a firewall log") is None


def test_dispatcher_selects_supported_parser() -> None:
    event = parse_log_line(
        "Sep 21 20:32:14 host sshd[123]: Failed password for admin "
        "from 203.0.113.42 port 54400 ssh2"
    )

    assert event is not None
    assert event.source == "linux_ssh"


def test_dispatcher_returns_none_for_unsupported_line() -> None:
    assert parse_log_line("synthetic unsupported line") is None
