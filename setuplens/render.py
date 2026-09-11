"""Portable report formats; HTML ships with no external assets or requests."""

from __future__ import annotations

import html
from pathlib import Path

from .scanner import Report, redact

LIMITATION = "Static setup review, not a security verdict. Findings are heuristics; no findings does not mean safe. Dependencies, generated code and runtime behavior are not analyzed."


def text_report(report: Report) -> str:
    counts = report.to_dict()["summary"]
    out = [f"SetupLens / {report.project}", "Understand the setup before you run it.", "", f"{len(report.files)} setup files | {', '.join(report.ecosystems) or 'No supported ecosystem detected'}", ""]
    if report.runtimes:
        out.append("RUNTIMES")
        out.extend(f"  {r['name']}: {r['value']} ({r['path']}:{r['line']})" for r in report.runtimes)
    if report.commands:
        out += ["", "DECLARED COMMANDS (not executed)"]
        out.extend(f"  {c['name']}: {c['command']} ({c['path']}:{c['line']})" for c in report.commands)
    if report.services:
        out += ["", "CONTAINER SETTINGS"]
        out.extend(f"  {s['name']}: {s['value']} ({s['path']}:{s['line']})" for s in report.services)
    if report.environment:
        out += ["", "ENVIRONMENT TEMPLATE NAMES (values omitted)"]
        out.extend(f"  {e['name']} ({e['path']}:{e['line']})" for e in report.environment)
    out += ["", f"REVIEW NOTES | {counts['high']} high | {counts['medium']} medium | {counts['info']} info", ""]
    for f in report.findings:
        out += [f"[{f.priority.upper()}] {f.rule} {f.title}", f"  {f.path}:{f.line}", f"  {f.evidence}", f"  Next: {f.action}", ""]
    if report.notes:
        out += ["", "SCAN NOTES", *[f"  - {n}" for n in report.notes]]
    out += ["", LIMITATION, "Review before sharing: display masking is best-effort."]
    return redact("\n".join(out)) + "\n"


def markdown_report(report: Report) -> str:
    # A fenced plain-text report is robust against Markdown in repository data.
    text = text_report(report)
    longest = max((len(part) for part in __import__("re").findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"# SetupLens report\n\n{fence}text\n{text}{fence}\n"


def html_report(report: Report) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    data = report.to_dict()
    counts = data["summary"]
    css = Path(__file__).with_name("report.css").read_text(encoding="utf-8")
    js = Path(__file__).with_name("report.js").read_text(encoding="utf-8")

    def source(path, line):
        return f'<span class="source">{esc(path)}<b>:{int(line)}</b></span>'

    cards = []
    for index, f in enumerate(report.findings):
        cards.append(f'''<article class="finding" data-priority="{esc(f.priority)}" id="finding-{index}">
<div class="finding-top"><span class="badge {esc(f.priority)}">{esc(f.priority)}</span><span class="rule">{esc(f.rule)}</span>{source(f.path, f.line)}</div>
<h3>{esc(f.title)}</h3><pre><code>{esc(f.evidence)}</code></pre>
<p>{esc(f.why)}</p><details><summary>What to check</summary><p>{esc(f.action)}</p></details></article>''')

    def inventory(title, records, body):
        return f'<section class="inventory"><h3>{title}<span>{len(records)}</span></h3>' + ("".join(body(r) for r in records) or '<p class="muted">None detected in supported files.</p>') + '</section>'

    runtime_html = inventory("Runtime requirements", report.runtimes, lambda r: f'<div class="inventory-row"><b>{esc(r["name"])}</b><code>{esc(r["value"])}</code>{source(r["path"], r["line"])}</div>')
    service_html = inventory("Container settings", report.services, lambda r: f'<div class="inventory-row"><b>{esc(r["name"])}</b><code>{esc(r["value"])}</code>{source(r["path"], r["line"])}</div>')
    command_html = inventory("Declared commands", report.commands, lambda r: f'<div class="inventory-row"><b>{esc(r["name"])} {"<span class=hook>lifecycle</span>" if r["automatic"] else ""}</b><code>{esc(r["command"])}</code>{source(r["path"], r["line"])}</div>')
    env_html = inventory("Environment names", report.environment, lambda r: f'<div class="inventory-row env"><code>{esc(r["name"])}</code>{"<span class=hook>sensitive name</span>" if r["sensitive_name"] else ""}{source(r["path"], r["line"])}</div>')
    note_html = "".join(f'<li>{esc(n)}</li>' for n in report.notes)
    file_html = "".join(f'<li><code>{esc(p)}</code></li>' for p in report.files)
    ecosystem_html = "".join(f'<span>{esc(e)}</span>' for e in report.ecosystems)
    hooks = sum(c['automatic'] for c in report.commands)
    guide_html = f'''<section class="setup-guide"><div class="section-top"><div><p class="eyebrow">01 / GET ORIENTED</p><h2>Before the first run</h2></div><div class="ecosystems">{ecosystem_html}</div></div><div class="guide-grid"><a href="#runtime"><span>01</span><b>Check your tools</b><p>{len(report.runtimes)} runtime declarations to compare with your environment.</p></a><a href="#services"><span>02</span><b>Prepare the services</b><p>Inspect container images and published ports before starting them.</p></a><a href="#environment"><span>03</span><b>Fill in configuration</b><p>{len(report.environment)} environment names found in example files. Values stay out of this report.</p></a><a href="#commands"><span>04</span><b>Read the entry points</b><p>{len(report.commands)} command declarations, including {hooks} lifecycle or build hooks.</p></a></div></section>'''
    runtime_html = runtime_html.replace('class="inventory"', 'class="inventory" id="runtime"', 1)
    service_html = service_html.replace('class="inventory"', 'class="inventory" id="services"', 1)
    command_html = command_html.replace('class="inventory"', 'class="inventory" id="commands"', 1)
    env_html = env_html.replace('class="inventory"', 'class="inventory" id="environment"', 1)
    footprint_html = f'<section class="footprint"><div class="inventory-grid">{runtime_html}{service_html}{command_html}{env_html}</div><p class="muted">These are source declarations, not a tested installation plan. Variable values, execution order and service availability are not verified.</p></section>'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="dark light"><title>SetupLens · {esc(report.project)}</title><style>{css}</style></head>
<body><a class="skip" href="#findings">Skip to findings</a>
<header><a class="brand" href="#top" aria-label="SetupLens report"><span class="brand-mark" aria-hidden="true">S<span>↗</span></span>SetupLens<span class="version">v{esc(report.version)}</span></a><span class="local"><span aria-hidden="true">●</span> LOCAL ANALYSIS</span></header>
<main id="top"><section class="hero"><div><p class="eyebrow">KNOW BEFORE YOU RUN</p><h1>New repo.<br>Clearer first steps.</h1><p class="lede">An onboarding map for <strong>{esc(report.project)}</strong>.<br>Tools, services, configuration and entry points — in one place.</p></div><div class="hero-note"><span class="orbit" aria-hidden="true">◎</span><p>Read the setup.<br><strong>Don't execute it.</strong></p><span>Local files · No models · No network</span></div></section>
<section class="stats" aria-label="Report summary"><div><b>{len(report.files):02}</b><span>Setup files inspected</span></div><div><b>{len(report.ecosystems):02}</b><span>Ecosystems detected</span></div><div><b class="medium-number">{hooks:02}</b><span>Lifecycle / build hooks</span></div><div><b>{len(report.environment):02}</b><span>Environment names</span></div></section>
<div class="boundary"><span aria-hidden="true">ⓘ</span><p><strong>See where it comes from.</strong> Each declaration names a source location. The scanner reads supported setup files without installing, importing or executing the project.</p></div>
{guide_html}{footprint_html}
<section class="workbench" id="findings"><div class="section-top"><div><p class="eyebrow">02 / REVIEW</p><h2>What deserves a look</h2></div><button class="print-button" id="print" type="button">Print report <span aria-hidden="true">↗</span></button></div><p class="muted">{esc(LIMITATION)}</p>
<div class="filters" aria-label="Filter findings"><div class="filter-buttons"><button type="button" class="selected" data-filter="all" aria-pressed="true">All <span>{len(report.findings)}</span></button><button type="button" data-filter="high" aria-pressed="false">High <span>{counts['high']}</span></button><button type="button" data-filter="medium" aria-pressed="false">Medium <span>{counts['medium']}</span></button><button type="button" data-filter="info" aria-pressed="false">Info <span>{counts['info']}</span></button></div><label class="search"><span class="sr-only">Search findings</span><span aria-hidden="true">⌕</span><input id="search" type="search" placeholder="Search files, rules, commands…" autocomplete="off"></label></div>
<p class="result-count" id="count" role="status" aria-live="polite">{len(report.findings)} findings</p>
<div class="finding-grid">{"".join(cards)}</div><p id="empty" class="empty" {"" if not cards else "hidden"}>No matching findings. Check the scan coverage and limitations below.</p></section>
<section class="coverage"><p class="eyebrow">03 / COVERAGE</p><h2>Know what was inspected</h2><details><summary>{len(report.files)} files inspected</summary><ul class="file-list">{file_html}</ul></details>{f'<ul class="notes">{note_html}</ul>' if note_html else ''}<p class="muted">Read-only snapshot. Symlinks and reparse points are skipped. Dependency trees, real .env files, README instructions and generated behavior are outside this report. Review source files before making a trust decision. Display masking is best-effort; inspect this report before sharing.</p></section>
</main><footer><span>SetupLens <b>·</b> Open source, by design.</span><span>OFFLINE REPORT / SCHEMA {report.schema_version}</span></footer><script>{js}</script></body></html>'''
