from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import typer
from dotenv import load_dotenv

from src.formatting import format_count
from src.orca_client import ComplianceMetrics, OrcaClient
from src.pptx_filler import fill_template

load_dotenv()

TEMPLATES_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path(__file__).parent / "output"

TEMPLATE_BY_LANG = {
    "pt": TEMPLATES_DIR / "poc_report_pt.pptx",
    "es": TEMPLATES_DIR / "poc_report_es.pptx",
}

# Slide 8 caps the compliance framework list (the leading "total
# controls" line is added on top of this).
COMPLIANCE_FRAMEWORK_CAP = 5

# Slide 8 prefix for the leading total-count line, per language.
COMPLIANCE_TOTAL_PREFIX = {
    "pt": "{n} controles avaliados",
    "es": "{n} controles evaluados",
}

app = typer.Typer(add_completion=False)


def _require_api_token() -> None:
    """Fail fast with a clear message if the API token is missing or empty.

    Without this guard, the first Orca request raises deep inside httpx
    once the server returns 401, which is harder to read and slower.
    """
    token = (os.environ.get("ORCA_API_TOKEN") or "").strip()
    if not token:
        typer.secho(
            "ORCA_API_TOKEN is missing. Copy .env.example to .env and set a real token.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)


def _fetch_metrics():
    with OrcaClient() as client:
        vuln = client.get_vulnerability_metrics()
        assets = client.get_asset_metrics()
        iam = client.get_identity_metrics()
        findings = client.get_findings_metrics()
        compliance = client.get_compliance_metrics()
    counts = {
        "vuln": vuln.as_dict(),
        "assets": assets.as_dict(),
        "iam": iam.as_dict(),
        "findings": findings.as_dict(),
    }
    return counts, compliance


def _display_metrics(metrics: dict, lang: str) -> dict:
    """Convert raw numeric metrics into locale-formatted strings for template tokens."""
    return {
        "metrics": {
            group: {k: format_count(v, lang) for k, v in values.items()}
            for group, values in metrics.items()
        }
    }


def _compliance_bullets(compliance: ComplianceMetrics, lang: str) -> list[str]:
    total_line = COMPLIANCE_TOTAL_PREFIX[lang].format(n=compliance.total_count)
    framework_lines = [
        f"{fw.display_name} - {fw.avg_score_percent}%"
        for fw in compliance.frameworks[:COMPLIANCE_FRAMEWORK_CAP]
    ]
    return [total_line, *framework_lines]


@app.command()
def main(
    lang: str = typer.Option(..., "--lang", help="Template language: pt or es"),
    output: Path | None = typer.Option(None, "--output", help="Output .pptx path"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print metrics, do not generate .pptx"),
) -> None:
    """Generate a POC report .pptx for the current Orca tenant."""
    if lang not in TEMPLATE_BY_LANG:
        raise typer.BadParameter(f"--lang must be one of: {list(TEMPLATE_BY_LANG)}")

    _require_api_token()

    typer.echo(f"Fetching metrics for --lang {lang}")
    metrics, compliance = _fetch_metrics()

    if dry_run:
        for group, values in metrics.items():
            typer.echo(f"\n[{group}]")
            for key, value in values.items():
                typer.echo(f"  {key}: {value}")
        typer.echo(f"\n[compliance]")
        typer.echo(f"  total_count: {compliance.total_count}")
        for fw in compliance.frameworks[:COMPLIANCE_FRAMEWORK_CAP]:
            typer.echo(f"  - {fw.display_name}: {fw.avg_score_percent}%")
        return

    template_path = TEMPLATE_BY_LANG[lang]
    if not template_path.exists():
        raise typer.BadParameter(
            f"Template not found: {template_path}. Add it before running (see README)."
        )

    if output is None:
        output = OUTPUT_DIR / f"poc_report_{lang}_{date.today().isoformat()}.pptx"

    typer.echo(f"Filling template {template_path.name} -> {output}")
    fill_template(
        template_path=template_path,
        output_path=output,
        data=_display_metrics(metrics, lang),
        bullet_blocks={8: _compliance_bullets(compliance, lang)},
    )
    typer.echo(f"Done: {output}")


if __name__ == "__main__":
    app()
