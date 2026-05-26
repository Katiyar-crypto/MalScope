"""
MalScope report generator.
Exports analysis results in JSON, HTML, Markdown, and SARIF formats.
"""

import html
import json
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Iterable


VERSION = "2.1.0"


def generate_report(result: Dict, output_path: str, fmt: str = "html") -> bool:
    try:
        fmt = fmt.lower().strip()
        if fmt == "json":
            return _export_json(result, output_path)
        if fmt == "html":
            return _export_html(result, output_path)
        if fmt in ("md", "markdown"):
            return _export_markdown(result, output_path)
        if fmt == "sarif":
            return _export_sarif(result, output_path)
        if fmt == "bundle":
            return _export_bundle(result, output_path)
        return False
    except Exception as e:
        print(f"Report generation error: {e}")
        return False


def _export_json(result: Dict, path: str) -> bool:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return True


def _h(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _rows(items: Iterable[str]) -> str:
    return "".join(f"<li>{_h(item)}</li>" for item in items)


def _export_html(result: Dict, path: str) -> bool:
    behavior = result.get("behavior", {})
    decompile = result.get("decompile", {})
    universal = result.get("universal", {})
    yara = result.get("yara", {})

    score = int(behavior.get("threat_score", 0) or 0)
    confidence = int(behavior.get("confidence_score", 0) or 0)
    score_color = (
        "#81c784" if score < 30 else
        "#ff9800" if score < 60 else
        "#ef5350" if score < 80 else
        "#b71c1c"
    )
    score_label = (
        "LOW" if score < 30 else
        "MEDIUM" if score < 60 else
        "HIGH" if score < 80 else
        "CRITICAL"
    )

    sev_colors = {"CRITICAL": "#ef5350", "HIGH": "#ff9800", "MEDIUM": "#ffeb3b", "LOW": "#81c784"}

    indicators_html = ""
    for ind in behavior.get("indicators", []):
        sev = ind.get("severity", "LOW")
        color = sev_colors.get(sev, "#fff")
        indicators_html += f"""
        <tr>
            <td style="color:{color};font-weight:bold">{_h(sev)}</td>
            <td>{_h(ind.get('category',''))}</td>
            <td>{_h(ind.get('description',''))}</td>
            <td><code>{_h(ind.get('evidence',''))}</code></td>
            <td><a href="{_h(ind.get('mitre_technique','#'))}" style="color:#58a6ff">{_h(ind.get('mitre_id',''))}</a></td>
        </tr>"""

    iocs_html = ""
    for ioc_type, values in behavior.get("iocs", {}).items():
        for val in values:
            iocs_html += f"<tr><td>{_h(ioc_type.replace('_',' ').title())}</td><td><code>{_h(val)}</code></td></tr>"

    yara_html = ""
    for match in yara.get("matches", []):
        sev = match.get("severity", "MEDIUM")
        color = sev_colors.get(sev, "#fff")
        yara_html += f"""
        <tr>
            <td>{_h(match.get('rule_name',''))}</td>
            <td style="color:{color}">{_h(sev)}</td>
            <td>{_h(match.get('meta',{}).get('description',''))}</td>
        </tr>"""

    obf_html = _rows(behavior.get("obfuscation_detected", [])) or "<li>None detected</li>"
    facts_html = _rows(behavior.get("observed_facts", [])[:20]) or "<li>None captured</li>"
    hypotheses_html = _rows(behavior.get("ai_hypotheses", [])[:20]) or "<li>None generated</li>"
    warnings_html = _rows(universal.get("warnings", []) or result.get("warnings", [])) or "<li>None</li>"
    families_html = _h(", ".join(behavior.get("malware_families", [])) or "None identified")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MalScope Report</title>
<style>
  body {{ font-family: Consolas, monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #8b949e; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-top: 24px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 8px 0; }}
  .score {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
  .score-label {{ color: {score_color}; font-size: 14px; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
  th {{ background: #21262d; color: #8b949e; padding: 6px 10px; text-align: left; border-bottom: 1px solid #30363d; }}
  td {{ padding: 5px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  code {{ background: #21262d; padding: 1px 5px; border-radius: 3px; font-size: 10px; }}
  .meta {{ color: #8b949e; font-size: 10px; }}
  ul {{ color: #ffb74d; }}
  footer {{ color: #484f58; font-size: 10px; text-align: center; margin-top: 30px; border-top: 1px solid #21262d; padding-top: 10px; }}
</style>
</head>
<body>
<h1>MalScope Forensic Analysis Report</h1>
<p class="meta">Generated: {_h(now)}</p>

<div class="card">
  <div class="score">{score}</div>
  <div class="score-label">Threat Level: {_h(score_label)}</div>
  <p>Confidence: {confidence}%</p>
  <p>{_h(behavior.get('summary',''))}</p>
</div>

<div class="card">
  <h2>File Metadata</h2>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Type</td><td>{_h(universal.get('file_type', decompile.get('python_version','Unknown')))}</td></tr>
    <tr><td>Backend</td><td>{_h(decompile.get('backend_used', universal.get('backend_used','Unknown')))}</td></tr>
    <tr><td>Success</td><td>{_h(decompile.get('success', universal.get('success', False)))}</td></tr>
    <tr><td>MD5</td><td><code>{_h(universal.get('md5',''))}</code></td></tr>
    <tr><td>SHA256</td><td><code>{_h(universal.get('sha256',''))}</code></td></tr>
    <tr><td>Malware Families</td><td>{families_html}</td></tr>
  </table>
</div>

<div class="card">
  <h2>Threat Indicators ({len(behavior.get('indicators',[]))})</h2>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Description</th><th>Evidence</th><th>MITRE</th></tr>
    {indicators_html or '<tr><td colspan="5">No indicators detected</td></tr>'}
  </table>
</div>

<div class="card"><h2>Warnings</h2><ul>{warnings_html}</ul></div>
<div class="card"><h2>Obfuscation Techniques</h2><ul>{obf_html}</ul></div>

<div class="card">
  <h2>Indicators of Compromise</h2>
  <table>
    <tr><th>Type</th><th>Value</th></tr>
    {iocs_html or '<tr><td colspan="2">No IOCs extracted</td></tr>'}
  </table>
</div>

<div class="card"><h2>Observed Facts</h2><ul>{facts_html}</ul></div>
<div class="card"><h2>AI Hypotheses</h2><ul>{hypotheses_html}</ul></div>

<div class="card">
  <h2>YARA Scan Results ({len(yara.get('matches',[]))} matches)</h2>
  <p class="meta">Engine: {_h(yara.get('engine', 'yara-python'))} | Rules loaded: {_h(yara.get('rules_loaded', ''))} | Status: {_h(yara.get('error', 'OK') or 'OK')}</p>
  <table>
    <tr><th>Rule</th><th>Severity</th><th>Description</th></tr>
    {yara_html or '<tr><td colspan="3">No YARA matches</td></tr>'}
  </table>
</div>

<footer>Generated by MalScope v{VERSION} - For educational and research use only</footer>
</body>
</html>"""

    Path(path).write_text(html_doc, encoding="utf-8")
    return True


def _export_markdown(result: Dict, path: str) -> bool:
    behavior = result.get("behavior", {})
    yara = result.get("yara", {})
    universal = result.get("universal", {})
    lines = [
        "# MalScope Forensic Analysis Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Threat score: {behavior.get('threat_score', 0)}",
        f"Confidence: {behavior.get('confidence_score', 0)}%",
        f"File type: {universal.get('file_type', 'Unknown')}",
        f"SHA256: {universal.get('sha256', '')}",
        "",
        "## Summary",
        behavior.get("summary", ""),
        "",
        "## Threat Indicators",
    ]
    for ind in behavior.get("indicators", []):
        lines.append(f"- {ind.get('severity','')} {ind.get('category','')}: {ind.get('description','')} ({ind.get('evidence','')})")
    if not behavior.get("indicators"):
        lines.append("- None detected")

    lines.extend(["", "## IOCs"])
    for ioc_type, values in behavior.get("iocs", {}).items():
        for val in values:
            lines.append(f"- {ioc_type}: `{val}`")
    if not behavior.get("iocs"):
        lines.append("- None extracted")

    lines.extend(["", "## YARA"])
    for match in yara.get("matches", []):
        lines.append(f"- {match.get('severity','')} {match.get('rule_name','')}: {match.get('meta',{}).get('description','')}")
    if not yara.get("matches"):
        lines.append("- No matches")

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def _export_sarif(result: Dict, path: str) -> bool:
    behavior = result.get("behavior", {})
    rules = {}
    results = []
    for ind in behavior.get("indicators", []):
        rule_id = ind.get("mitre_id") or ind.get("description") or "MalScope.Indicator"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": ind.get("description", rule_id),
            "shortDescription": {"text": ind.get("description", "")},
            "helpUri": ind.get("mitre_technique", ""),
        })
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(ind.get("severity", "LOW")),
            "message": {"text": f"{ind.get('category','')}: {ind.get('evidence','')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sample"}}}],
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MalScope",
                    "version": VERSION,
                    "informationUri": "https://attack.mitre.org/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return True


def _sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(str(severity).upper(), "warning")


def _export_bundle(result: Dict, path: str) -> bool:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        files = {
            "report.html": ("html", base / "report.html"),
            "report.md": ("md", base / "report.md"),
            "report.json": ("json", base / "report.json"),
            "report.sarif": ("sarif", base / "report.sarif"),
        }
        for _, (fmt, target) in files.items():
            generate_report(result, str(target), fmt)

        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for arcname, (_, target) in files.items():
                zf.write(target, arcname)

            for name, content in result.get("universal", {}).get("tabs", {}).items():
                safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in str(name)).strip() or "tab"
                zf.writestr(f"tabs/{safe_name}.txt", str(content))

    return True
