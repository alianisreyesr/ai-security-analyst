import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_release_metadata_is_consistent_and_documented() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    project = tomllib.loads((ROOT / "backend/pyproject.toml").read_text(encoding="utf-8"))
    package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    app = (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    assert version == "1.0.0"
    assert project["project"]["version"] == version
    assert package["version"] == version
    assert f'version="{version}"' in app
    assert f"## [{version}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert (ROOT / f"docs/releases/v{version}.md").is_file()
    assert "resume-ready bullets" in (ROOT / "PORTFOLIO.md").read_text(encoding="utf-8").lower()
    result = subprocess.run(
        [sys.executable, "scripts/check_version.py", "--expected", f"v{version}"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
