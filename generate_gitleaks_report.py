"""
Reads gitleaks-report.json and writes gitleaks-report.html.
Single self-contained script: template + generation logic.
"""

import html
import json
import os

REPORT_PATH = "gitleaks-report.json"
OUTPUT_PATH = "gitleaks-report.html"


def load_leaks(path: str) -> list:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return []


def _format_row(leak: dict) -> str:
    file_p = html.escape(str(leak.get("File", "N/A")))
    rule = html.escape(str(leak.get("RuleID", "N/A")))
    start_line = leak.get("StartLine", "-")
    commit = html.escape(str(leak.get("Commit", "N/A")))
    author = html.escape(str(leak.get("Author", "N/A")))
    match = html.escape(str(leak.get("Match", "REDACTED")))
    date = html.escape(str(leak.get("Date", "N/A")))
    commit_short = commit[:8] if len(commit) >= 8 else commit

    return f"""
    <tr class="hover:bg-gray-50 border-b border-gray-100">
        <td class="p-3"><span class="bg-red-100 text-red-800 text-xs font-semibold px-2.5 py-0.5 rounded border border-red-200">{rule}</span></td>
        <td class="p-3 font-mono text-sm text-gray-700"><b>{file_p}</b><br><span class="text-xs text-gray-500">Line: {start_line}</span></td>
        <td class="p-3 font-mono text-xs text-red-600 bg-red-50 p-2 rounded max-w-xs overflow-x-auto"><code>{match}</code></td>
        <td class="p-3 text-xs text-gray-600">
            <div><b>Author:</b> {author}</div>
            <div><b>Commit:</b> <span class="font-mono">{commit_short}</span></div>
            <div><b>Date:</b> {date}</div>
        </td>
    </tr>
    """


def render_html(leaks: list) -> str:
    total_leaks = len(leaks)
    status_color = "#ef4444" if total_leaks > 0 else "#10b981"
    status_text = (
        f"{total_leaks} Secret(s) Detected" if total_leaks > 0 else "No secrets detected"
    )

    if total_leaks == 0:
        rows_html = """
        <tr>
            <td colspan="4" class="p-8 text-center text-emerald-600 bg-emerald-50 font-medium">
                No secrets or credentials were detected in this scan.
            </td>
        </tr>
        """
    else:
        rows_html = "".join(_format_row(leak) for leak in leaks)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - Gitleaks</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen p-6 font-sans">
    <div class="max-w-6xl mx-auto bg-white shadow-lg rounded-xl overflow-hidden border border-gray-200">
        <div class="p-6 bg-slate-900 text-white flex justify-between items-center">
            <div>
                <h1 class="text-2xl font-bold flex items-center gap-2">Gitleaks Security Report</h1>
                <p class="text-slate-400 text-sm mt-1">Analysis of secrets and credential leaks in the repository</p>
            </div>
            <div>
                <span class="text-sm font-bold px-4 py-2 rounded-full text-white" style="background-color: {status_color}">
                    {status_text}
                </span>
            </div>
        </div>

        <div class="p-6 bg-slate-50 border-b border-gray-200 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
                <div class="text-gray-500 text-xs font-semibold uppercase">Total Leaks</div>
                <div class="text-2xl font-bold text-gray-800 mt-1">{total_leaks}</div>
            </div>
            <div class="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
                <div class="text-gray-500 text-xs font-semibold uppercase">CI Status</div>
                <div class="text-2xl font-bold mt-1" style="color: {status_color}">
                    {"FAILED" if total_leaks > 0 else "PASSED"}
                </div>
            </div>
            <div class="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
                <div class="text-gray-500 text-xs font-semibold uppercase">Tool</div>
                <div class="text-2xl font-bold text-gray-800 mt-1">Gitleaks v8</div>
            </div>
        </div>

        <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-gray-100 text-gray-600 text-xs uppercase border-b border-gray-200">
                        <th class="p-3">Rule / Type</th>
                        <th class="p-3">File &amp; Line</th>
                        <th class="p-3">Masked Excerpt</th>
                        <th class="p-3">Author &amp; Commit</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>

        <div class="p-4 bg-gray-50 border-t border-gray-200 text-xs text-gray-600">
            <p class="font-semibold mb-2">Ignore a false positive:</p>
            <ul>
                <li>• JS / TS / Java / C# / Go / PHP &nbsp;&mdash;&gt;&nbsp; <code class="bg-gray-200 px-1 py-0.5 rounded text-red-600">// gitleaks:allow</code></li>
                <li>• Python / Bash / YAML / Docker &nbsp;&mdash;&gt;&nbsp; <code class="bg-gray-200 px-1 py-0.5 rounded text-red-600"># gitleaks:allow</code></li>
                <li>• HTML / XML &nbsp;&mdash;&gt;&nbsp; <code class="bg-gray-200 px-1 py-0.5 rounded text-red-600">&lt;!-- gitleaks:allow --&gt;</code></li>
                <li>• CSS &nbsp;&mdash;&gt;&nbsp; <code class="bg-gray-200 px-1 py-0.5 rounded text-red-600">/* gitleaks:allow */</code></li>
                <li>• SQL &nbsp;&mdash;&gt;&nbsp; <code class="bg-gray-200 px-1 py-0.5 rounded text-red-600">-- gitleaks:allow</code></li>
            </ul>
        </div>
    </div>
</body>
</html>
"""


def main() -> None:
    leaks = load_leaks(REPORT_PATH)
    html_content = render_html(leaks)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report generated successfully: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
