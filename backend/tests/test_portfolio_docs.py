from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
README = REPOSITORY_ROOT / "README.md"
PLAN = REPOSITORY_ROOT / "AI_SECURITY_ANALYST_PLAN.md"
REQUIRED_GUIDES = (
    "docs/ARCHITECTURE.md",
    "docs/API_REFERENCE.md",
    "docs/CONFIGURATION.md",
    "docs/DEMO.md",
    "docs/DEPLOYMENT.md",
    "docs/RELEASE_QUALITY_GATE.md",
    "docs/UI_ACCESSIBILITY.md",
    "docs/RELEASING.md",
    "docs/releases/v1.0.0.md",
    "PORTFOLIO.md",
)


def test_portfolio_documentation_is_current_and_linked() -> None:
    readme = README.read_text(encoding="utf-8")
    plan = PLAN.read_text(encoding="utf-8")

    for relative_path in REQUIRED_GUIDES:
        assert (REPOSITORY_ROOT / relative_path).is_file()
        assert relative_path in readme

    assert "Planning / v0.1" not in plan
    assert "Tailwind CSS" not in readme
    assert "Tailwind CSS" not in plan
    assert "v1.0.0 stable release" in readme
