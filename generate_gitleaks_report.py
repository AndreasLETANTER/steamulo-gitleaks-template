#!/usr/bin/env python3
"""Rapport HTML Gitleaks au meme style que les rapports Trivy / KICS.

Usage:
    generate_gitleaks_report.py [gitleaks-report.json] [-o gitleaks-report.html]

Stdlib uniquement, HTML autonome (CSS/JS inline, aucun CDN).
Le champ "Secret" du JSON n'est jamais affiche.
"""
import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_REPORT = "gitleaks-report.json"
DEFAULT_OUT = "gitleaks-report.html"

CSS = """
:root { --secret: #6a1b9a; --files: #37474f; --rules: #1a237e; --commits: #455a64; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #212121; }

header { background: #1a237e; color: white; padding: 1.5rem 2rem; }
header h1 { font-size: 1.4rem; font-weight: 600; }
header p { opacity: .7; font-size: .85rem; margin-top: .3rem; }

.summary { display: flex; gap: 1rem; padding: 1.25rem 2rem; background: white; border-bottom: 1px solid #e0e0e0; flex-wrap: wrap; }
.card { flex: 1; min-width: 110px; border-radius: 8px; padding: .9rem 1.25rem; color: white; text-align: center; }
.card .count { font-size: 2.2rem; font-weight: 700; line-height: 1; }
.card .label { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; margin-top: .3rem; opacity: .9; }
.card-secrets { background: var(--secret); }
.card-files   { background: var(--files); }
.card-rules   { background: var(--rules); }
.card-commits { background: var(--commits); }

.notice { margin: 1.25rem 2rem 0; padding: .85rem 1.1rem; border-left: 4px solid #6a1b9a; background: #f3e5f5;
          font-size: .86rem; color: #4a148c; border-radius: 4px; }

.filters { padding: .75rem 2rem; background: white; display: flex; gap: .5rem; border-bottom: 1px solid #e0e0e0; align-items: center; flex-wrap: wrap; margin-top: 1.25rem; }
.filters span { font-size: .85rem; color: #757575; margin-right: .25rem; }
.filters select {
  padding: .35rem .75rem; border: 2px solid #e0e0e0; border-radius: 20px;
  font-size: .82rem; font-weight: 600; background: white; color: #424242; cursor: pointer; max-width: 320px;
}

.content { padding: 1.5rem 2rem; }

.target-group { background: white; border-radius: 8px; margin-bottom: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden; }
.target-header {
  background: #4a148c; color: white; padding: .85rem 1.25rem;
  display: flex; align-items: center; gap: .75rem; cursor: pointer; user-select: none;
}
.target-header:hover { background: #6a1b9a; }
.target-toggle { font-size: .8rem; transition: transform .2s; display: inline-block; }
.target-group.collapsed .target-toggle { transform: rotate(-90deg); }
.target-group.collapsed table { display: none; }
.target-name { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .9rem; font-weight: 600; flex: 1; word-break: break-all; }
.target-type { font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; padding: .2rem .55rem; border-radius: 4px; background: rgba(255,255,255,.15); }

table { width: 100%; border-collapse: collapse; }
th { padding: .65rem 1rem; text-align: left; font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
     white-space: nowrap; background: #eceff1; color: #455a64; border-bottom: 1px solid #cfd8dc; }
td { padding: .7rem 1rem; font-size: .88rem; border-bottom: 1px solid #f5f5f5; vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #fafafa; }
tr.row-hidden { display: none; }

.badge { display: inline-block; padding: .2rem .55rem; border-radius: 4px; font-size: .72rem; font-weight: 700; color: white; white-space: nowrap; }
.badge-secret { background: var(--secret); }

.line    { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; color: #455a64; }
.rule-desc { font-size: .78rem; color: #616161; margin-top: .3rem; max-width: 280px; }
.excerpt { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .78rem; color: #b71c1c; background: #fdecea;
           padding: .35rem .5rem; border-radius: 4px; max-width: 340px; overflow-x: auto; white-space: pre; }
.commit  { font-size: .78rem; color: #424242; white-space: nowrap; }
.commit .sha { font-family: 'SFMono-Regular', Consolas, monospace; }
.fp { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .72rem; color: #455a64; background: #eceff1;
      padding: .25rem .4rem; border-radius: 4px; cursor: pointer; display: inline-block; max-width: 220px;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: top; }
.fp.copied { background: #c8e6c9; color: #1b5e20; }

.empty { text-align: center; padding: 3rem; color: #2e7d32; font-size: .95rem; background: #e8f5e9; border-radius: 8px; font-weight: 600; }
.empty.warn { color: #92400e; background: #fffbeb; }
.target-group.all-hidden { display: none; }

.foot { padding: 0 2rem 2rem; font-size: .8rem; color: #616161; }
.foot h3 { font-size: .85rem; margin-bottom: .4rem; color: #424242; }
.foot ul { padding-left: 1.1rem; }
.foot li { margin-bottom: .2rem; }
.foot code { background: #e0e0e0; padding: .1rem .35rem; border-radius: 3px; font-size: .78rem; }
"""

JS = """
const groups = Array.from(document.querySelectorAll('.target-group'));
const rows = Array.from(document.querySelectorAll('tr[data-rule]'));
const targetSelect = document.getElementById('target-filter');
const ruleSelect = document.getElementById('rule-filter');

groups.forEach(g => {
  const opt = document.createElement('option');
  opt.value = g.dataset.target;
  opt.textContent = g.dataset.target;
  targetSelect.appendChild(opt);
});
Array.from(new Set(rows.map(r => r.dataset.rule))).sort().forEach(rule => {
  const opt = document.createElement('option');
  opt.value = rule;
  opt.textContent = rule;
  ruleSelect.appendChild(opt);
});

let currentRule = 'ALL';
let currentTarget = 'ALL';

function applyFilters() {
  rows.forEach(r => {
    const ruleMatch = currentRule === 'ALL' || r.dataset.rule === currentRule;
    const tgtMatch = currentTarget === 'ALL' || r.dataset.target === currentTarget;
    r.classList.toggle('row-hidden', !(ruleMatch && tgtMatch));
  });
  groups.forEach(g => {
    const visible = g.querySelectorAll('tr[data-rule]:not(.row-hidden)').length;
    g.classList.toggle('all-hidden', visible === 0);
  });
}
function setRuleFilter(v) { currentRule = v; applyFilters(); }
function setTargetFilter(v) { currentTarget = v; applyFilters(); }

document.querySelectorAll('.fp').forEach(el => {
  el.addEventListener('click', () => {
    const text = el.dataset.fp;
    const done = () => { el.classList.add('copied'); setTimeout(() => el.classList.remove('copied'), 1200); };
    if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done, () => {}); }
    else { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t);
           t.select(); try { document.execCommand('copy'); done(); } catch (e) {} t.remove(); }
  });
});
"""

FOOTER = """
<div class="foot">
  <h3>Ignore a false positive</h3>
  <ul>
    <li>JS / TS / Java / C# / Go / PHP &rarr; <code>// gitleaks:allow</code></li>
    <li>Python / Bash / YAML / Docker &rarr; <code># gitleaks:allow</code></li>
    <li>HTML / XML &rarr; <code>&lt;!-- gitleaks:allow --&gt;</code></li>
    <li>CSS &rarr; <code>/* gitleaks:allow */</code></li>
    <li>SQL &rarr; <code>-- gitleaks:allow</code></li>
    <li>Secret in git history (cannot be edited): click its <b>Fingerprint</b> to copy it and add it as a line
        in <code>.gitleaksignore</code>.</li>
  </ul>
</div>
"""


def esc(value):
    return html.escape(str(value), quote=True) if value is not None else ""


def load_leaks(path):
    """Liste des leaks, ou None si le fichier est absent / illisible.
    Un fichier vide ou une liste vide = aucun secret."""
    if not os.path.exists(path):
        return None
    if os.path.getsize(path) == 0:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"erreur de lecture JSON: {e}", file=sys.stderr)
        return None
    if data is None:
        return []
    return data if isinstance(data, list) else None


def masked_match(leak):
    """Extrait affichable : jamais le secret en clair, meme sans --redact."""
    match = str(leak.get("Match") or "REDACTED")
    secret = str(leak.get("Secret") or "")
    if secret and secret != "REDACTED" and len(secret) >= 4:
        match = match.replace(secret, "REDACTED")
    return match


def group_by_file(leaks):
    groups = {}
    for leak in leaks:
        groups.setdefault(leak.get("File") or "N/A", []).append(leak)
    for items in groups.values():
        items.sort(key=lambda x: (x.get("StartLine") or 0, str(x.get("Commit") or "")))
    return sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))


def render_row(leak, target):
    rule = leak.get("RuleID") or "N/A"
    desc = leak.get("Description") or ""
    line = leak.get("StartLine")
    line = f"L{line}" if line else "-"
    commit = str(leak.get("Commit") or "N/A")
    sha = commit[:8] if len(commit) >= 8 else commit
    fp = leak.get("Fingerprint") or ""
    fp_cell = (f'<span class="fp" data-fp="{esc(fp)}" title="Click to copy: {esc(fp)}">{esc(fp)}</span>'
               if fp else "")
    return (
        f'<tr data-rule="{esc(rule)}" data-target="{esc(target)}">'
        f'<td class="line">{esc(line)}</td>'
        f'<td><span class="badge badge-secret">{esc(rule)}</span>'
        f'<div class="rule-desc">{esc(desc)}</div></td>'
        f'<td><div class="excerpt">{esc(masked_match(leak))}</div></td>'
        f'<td class="commit"><div><span class="sha">{esc(sha)}</span></div>'
        f'<div>{esc(leak.get("Author") or "N/A")}</div><div>{esc(leak.get("Date") or "N/A")}</div></td>'
        f'<td>{fp_cell}</td>'
        f'</tr>'
    )


def render_group(target, items):
    rows = "".join(render_row(x, target) for x in items)
    n = len(items)
    return f"""
<div class="target-group" data-target="{esc(target)}">
  <div class="target-header" onclick="this.parentElement.classList.toggle('collapsed')">
    <span class="target-toggle">&#9660;</span>
    <span class="target-name">{esc(target)}</span>
    <span class="target-type">SECRET</span>
    <span class="badge badge-secret">{n} secret{'s' if n > 1 else ''}</span>
  </div>
  <table>
    <thead><tr><th>Line</th><th>Rule</th><th>Masked excerpt</th><th>Commit</th><th>Fingerprint</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""


def render_html(leaks):
    if leaks is None:
        subtitle = "Report not found"
        cards = ""
        filters = ""
        notice = ""
        content = ('<div class="empty warn">Gitleaks report not found or unreadable. '
                   "The scan probably failed before producing results, check the job log. "
                   "This is NOT a clean result.</div>")
    else:
        groups = group_by_file(leaks)
        n_rules = len({x.get("RuleID") for x in leaks})
        n_commits = len({x.get("Commit") for x in leaks})
        subtitle = (f"{len(leaks)} secret(s) detected" if leaks else "No secrets detected")
        cards = "".join(
            f'<div class="card card-{k}"><div class="count">{v}</div><div class="label">{label}</div></div>'
            for k, v, label in (("secrets", len(leaks), "Secrets"), ("files", len(groups), "Files"),
                                ("rules", n_rules, "Rules"), ("commits", n_commits, "Commits"))
        )
        notice = ('<div class="notice"><b>A secret that reached git history must be revoked / rotated</b>, '
                  "even if it is removed from the current code: it stays readable in old commits.</div>"
                  if leaks else "")
        filters = """
<div class="filters">
  <span>Rule:</span>
  <select id="rule-filter" onchange="setRuleFilter(this.value)"><option value="ALL">All rules</option></select>
  <span style="margin-left:1.5rem;">Source:</span>
  <select id="target-filter" onchange="setTargetFilter(this.value)"><option value="ALL">All sources</option></select>
</div>"""
        content = ("".join(render_group(t, items) for t, items in groups)
                   or '<div class="empty">No secrets or credentials were detected in this scan.</div>')

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gitleaks Security Report</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Gitleaks Security Report</h1>
  <p>{esc(subtitle)} &mdash; generated on {now}</p>
</header>
<div class="summary">{cards}</div>
{notice}
{filters}
<div class="content">{content}</div>
{FOOTER}
<script>{JS}</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="Rapport HTML a partir d'un rapport Gitleaks JSON.")
    ap.add_argument("report", nargs="?", default=DEFAULT_REPORT,
                    help=f"rapport JSON Gitleaks (defaut: {DEFAULT_REPORT})")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT,
                    help=f"fichier HTML de sortie (defaut: {DEFAULT_OUT})")
    ap.add_argument("--missing-is-clean", action="store_true",
                    help="traite un rapport absent comme 'aucun secret' (ancien comportement)")
    args = ap.parse_args()

    leaks = load_leaks(args.report)
    if leaks is None and args.missing_is_clean and not os.path.exists(args.report):
        leaks = []

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render_html(leaks))

    if leaks is None:
        print(f"attention: rapport introuvable/illisible ({args.report}), page d'avertissement ecrite", file=sys.stderr)
    else:
        print(f"rapport genere: {args.out} ({len(leaks)} secrets)", file=sys.stderr)


if __name__ == "__main__":
    main()
