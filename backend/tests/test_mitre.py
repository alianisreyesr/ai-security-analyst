from app.threat_intel.mitre import techniques_for_rule


def test_brute_force_maps_to_t1110() -> None:
    techniques = techniques_for_rule("auth.brute_force")

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1110"
    assert techniques[0].name == "Brute Force"


def test_port_scan_maps_to_t1046() -> None:
    techniques = techniques_for_rule("network.port_scan")

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1046"
    assert techniques[0].name == "Network Service Discovery"


def test_unsupported_rule_has_no_mitre_mapping() -> None:
    assert techniques_for_rule("web.request_burst") == ()
