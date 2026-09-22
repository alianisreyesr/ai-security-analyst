from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


_RULE_MAPPINGS: dict[str, tuple[MitreTechnique, ...]] = {
    "auth.brute_force": (
        MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic="Credential Access",
        ),
    ),
    "auth.brute_force_success": (
        MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic="Credential Access",
        ),
    ),
    "network.port_scan": (
        MitreTechnique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
        ),
    ),
}


def techniques_for_rule(rule_id: str) -> tuple[MitreTechnique, ...]:
    return _RULE_MAPPINGS.get(rule_id, ())
