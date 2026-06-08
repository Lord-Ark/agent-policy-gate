"""Render evaluation results for humans."""

from __future__ import annotations

import html
import json

from .models import EvaluationResult


def render_text(result: EvaluationResult) -> str:
    lines = [
        f"Policy: {result.policy_name} v{result.policy_version}",
        (
            "Summary: "
            f"{result.summary.total_events} events, "
            f"{result.summary.allowed} allow, "
            f"{result.summary.review} review, "
            f"{result.summary.denied} deny, "
            f"max risk {result.summary.highest_risk_score}"
        ),
        "",
    ]
    for finding in result.findings:
        event = finding.event
        lines.append(
            (
                f"[{finding.decision.upper()}] event={finding.event_index} "
                f"tool={event.tool_name if event else 'unknown'} "
                f"action={event.action if event else 'unknown'} "
                f"risk={finding.risk_score} "
                f"reason={finding.reason}"
            )
        )
    return "\n".join(lines)


def render_json(result: EvaluationResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_validation_json(issues) -> str:
    return json.dumps({"issues": [issue.to_dict() for issue in issues]}, indent=2)


def render_validation_text(issues) -> str:
    if not issues:
        return "Policy validation passed with no issues."
    lines = ["Policy validation issues:", ""]
    for issue in issues:
        lines.append(f"[{issue.severity.upper()}] {issue.path}: {issue.message}")
    return "\n".join(lines)


def render_sarif(result: EvaluationResult) -> str:
    rules = {}
    results = []
    for finding in result.findings:
        rule_id = finding.rule_id or f"default-{finding.decision}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.reason},
                "properties": {
                    "decision": finding.decision,
                    "severity": finding.severity,
                },
            }

        event = finding.event
        level = "note"
        if finding.decision == "deny":
            level = "error"
        elif finding.decision == "review":
            level = "warning"

        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": event.resource if event and event.resource else "agent-trace-event"
                }
            }
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": (
                        f"{finding.reason} "
                        f"(tool={event.tool_name if event else 'unknown'}, "
                        f"action={event.action if event else 'unknown'}, "
                        f"risk={finding.risk_score})"
                    )
                },
                "locations": [location],
                "properties": {
                    "eventIndex": finding.event_index,
                    "decision": finding.decision,
                    "severity": finding.severity,
                    "riskScore": finding.risk_score,
                    "metadata": event.metadata if event else {},
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-policy-gate",
                        "informationUri": "https://github.com/Lord-Ark/agent-policy-gate",
                        "rules": list(rules.values()),
                    }
                },
                "artifacts": [],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def render_html(result: EvaluationResult) -> str:
    rows = []
    for finding in result.findings:
        event = finding.event
        metadata = html.escape(json.dumps(event.metadata, indent=2)) if event else "{}"
        rows.append(
            "<tr>"
            f"<td>{finding.event_index}</td>"
            f"<td>{html.escape(finding.decision)}</td>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{finding.risk_score}</td>"
            f"<td>{html.escape(event.tool_name if event else '')}</td>"
            f"<td>{html.escape(event.action if event else '')}</td>"
            f"<td>{html.escape(event.resource if event else '')}</td>"
            f"<td>{html.escape(finding.reason)}</td>"
            f"<td><pre>{metadata}</pre></td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Policy Gate Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f1e8;
      --card: #fffdf8;
      --ink: #1d1a16;
      --accent: #0d6b57;
      --danger: #a12b2b;
      --warn: #9a6700;
      --line: #d9cfbf;
    }}
    body {{
      margin: 0;
      font-family: Georgia, "Iowan Old Style", serif;
      background:
        radial-gradient(circle at top left, rgba(13,107,87,0.1), transparent 30%),
        linear-gradient(180deg, #f8f4ec 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 64px;
    }}
    .hero, .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 18px 48px rgba(29,26,22,0.08);
    }}
    .hero {{
      padding: 28px;
      margin-bottom: 20px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }}
    .stat {{
      padding: 14px;
      border-radius: 14px;
      background: #faf6ef;
      border: 1px solid var(--line);
    }}
    .stat strong {{
      display: block;
      font-size: 1.5rem;
      margin-top: 8px;
    }}
    .card {{
      padding: 20px;
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-family: "SFMono-Regular", Menlo, monospace;
      font-size: 0.9rem;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      padding: 10px 8px;
    }}
    th {{
      font-size: 0.76rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}
    .allow {{ color: var(--accent); }}
    .deny {{ color: var(--danger); }}
    .review {{ color: var(--warn); }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p>Agent Policy Gate</p>
      <h1>{html.escape(result.policy_name)} <span>v{html.escape(result.policy_version)}</span></h1>
      <p>Security posture report for AI agent tool execution traces.</p>
      <div class="stats">
        <div class="stat">Events<strong>{result.summary.total_events}</strong></div>
        <div class="stat">Allow<strong class="allow">{result.summary.allowed}</strong></div>
        <div class="stat">Review<strong class="review">{result.summary.review}</strong></div>
        <div class="stat">Deny<strong class="deny">{result.summary.denied}</strong></div>
        <div class="stat">Max Risk<strong>{result.summary.highest_risk_score}</strong></div>
      </div>
    </section>
    <section class="card">
      <table>
        <thead>
          <tr>
            <th>Event</th>
            <th>Decision</th>
            <th>Severity</th>
            <th>Risk</th>
            <th>Tool</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Reason</th>
            <th>Metadata</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""
