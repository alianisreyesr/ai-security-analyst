from pathlib import Path

from app.core.config import Settings

ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"


def test_env_example_documents_every_application_setting() -> None:
    documented = {
        line.split("=", 1)[0]
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    expected = {name.upper() for name in Settings.model_fields}

    assert expected <= documented, f"Missing settings: {sorted(expected - documented)}"
