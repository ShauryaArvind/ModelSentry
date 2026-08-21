import os
import sys
import json
import argparse
import urllib.request
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner import scan_file, load_custom_rules_file, load_ignore_file

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

console = Console()

def load_config_file(config_path=None):
    """
    Loads configuration settings from .modelsentryrc or modelsentry.json.
    """
    config = {
        "blocklist": None,
        "allowlist": None,
        "ignore_file": None,
        "threads": 4,
        "max_size_mb": None,
        "min_severity": "SAFE"
    }
    paths_to_check = [config_path] if config_path else [".modelsentryrc", "modelsentry.json"]
    for path in paths_to_check:
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    config.update(data)
                    break
            except Exception:
                pass
    return config

def get_all_files(path, recursive=False):
    """
    Collects all file paths to scan, filtering out version control,
    virtualenvs, and caches.
    """
    files = []
    if os.path.isfile(path):
        files.append(path)
    elif os.path.isdir(path):
        for root, dirs, filenames in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ('.git', '.venv', 'venv', '__pycache__', '.pytest_cache', '.agents', '.antigravity-ide')]
            for filename in filenames:
                files.append(os.path.join(root, filename))
            if not recursive:
                break
    return files

def handle_url_scan(url, is_json=False, custom_blocklist=None, custom_allowlist=None, ignore_file=None):
    """
    Downloads a file to a temporary location and scans it.
    """
    if not is_json:
        console.print(f"[bold blue]Downloading file from URL:[/bold blue] {url}")
        
    try:
        ext = os.path.splitext(url.split('?')[0])[1]
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as temp_file:
            temp_path = temp_file.name
            
        if not is_json:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                progress.add_task(description="Downloading...", total=None)
                urllib.request.urlretrieve(url, temp_path)
        else:
            urllib.request.urlretrieve(url, temp_path)
            
        result = scan_file(temp_path, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist, ignore_file=ignore_file)
        result["filepath"] = url
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        return result
    except Exception as e:
        return {
            "filepath": url,
            "sha256": "N/A",
            "file_type": "none",
            "verdict": "SUSPICIOUS",
            "risk_score": 5.0,
            "severity": "MEDIUM",
            "reasons": [f"Failed to download/scan URL: {str(e)}"],
            "details": {}
        }

def handle_hf_scan(repo_id, revision="main", is_json=False, custom_blocklist=None, custom_allowlist=None, ignore_file=None, threads=4):
    """
    Scans model weight artifacts in a remote Hugging Face repository without cloning the whole model repo.
    """
    clean_repo = repo_id.replace("https://huggingface.co/", "").strip('/')
    if not is_json:
        console.print(f"[bold blue]Fetching Hugging Face model repository metadata:[/bold blue] {clean_repo} (branch: {revision})")
    
    api_url = f"https://huggingface.co/api/models/{clean_repo}/tree/{revision}"
    req = urllib.request.Request(api_url, headers={'User-Agent': 'ModelSentry-Scanner/2.0'})
    
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return [{
            "filepath": clean_repo,
            "sha256": "N/A",
            "file_type": "none",
            "verdict": "SUSPICIOUS",
            "risk_score": 5.0,
            "severity": "MEDIUM",
            "reasons": [f"Failed to query Hugging Face API for '{clean_repo}': {str(e)}"],
            "details": {}
        }]
        
    model_exts = ('.safetensors', '.bin', '.pt', '.pth', '.h5', '.onnx', '.gguf', '.pkl', '.npz', '.npy')
    target_files = [item['path'] for item in data if isinstance(item, dict) and item.get('type') == 'file' and item.get('path', '').lower().endswith(model_exts)]
    
    if not target_files:
        return [{
            "filepath": clean_repo,
            "sha256": "N/A",
            "file_type": "none",
            "verdict": "SAFE",
            "risk_score": 0.0,
            "severity": "SAFE",
            "reasons": [f"No model weight artifacts found in repository root on branch '{revision}'"],
            "details": {}
        }]
        
    if not is_json:
        console.print(f"[bold green]Found {len(target_files)} model weight artifact(s) in Hugging Face repository.[/bold green]")
        
    urls = [f"https://huggingface.co/{clean_repo}/resolve/{revision}/{fpath}" for fpath in target_files]
    results = []
    
    if len(urls) > 1 and threads > 1:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {
                executor.submit(handle_url_scan, u, is_json=is_json, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist, ignore_file=ignore_file): u
                for u in urls
            }
            for future in as_completed(future_to_url):
                results.append(future.result())
    else:
        for u in urls:
            results.append(handle_url_scan(u, is_json=is_json, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist, ignore_file=ignore_file))
            
    return results

def init_pre_commit_hook(force=False):
    """
    Installs a Git pre-commit hook into .git/hooks/pre-commit to scan staged model files.
    """
    git_dir = ".git"
    if not os.path.exists(git_dir):
        console.print("[bold red]Error:[/bold red] Not a git repository (no .git folder found). Run 'git init' first.")
        return False
        
    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-commit")
    
    if os.path.exists(hook_path) and not force:
        console.print(f"[bold yellow]Pre-commit hook already exists at '{hook_path}'.[/bold yellow] Use --force to overwrite.")
        return False
        
    hook_script = """#!/bin/sh
# ModelSentry Pre-Commit Hook — Prevents committing unsafe AI model weight artifacts
echo "🛡️ ModelSentry Pre-Commit Check..."
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(pkl|pt|pth|h5|safetensors|gguf|onnx|npy|npz)$')

if [ -z "$STAGED_FILES" ]; then
    echo "No staged model artifacts found. Skipping scan."
    exit 0
fi

echo "Scanning staged model files:"
echo "$STAGED_FILES"

python modelsentry.py scan $STAGED_FILES
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "❌ ModelSentry detected security issues in staged model files! Commit aborted."
    exit 1
fi

echo "✅ ModelSentry pre-commit check passed!"
exit 0
"""
    with open(hook_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(hook_script)
        
    try:
        os.chmod(hook_path, 0o755)
    except Exception:
        pass
        
    console.print(f"[bold green]Successfully installed ModelSentry pre-commit hook to:[/bold green] {hook_path}")
    return True


def print_rich_report(results):
    """
    Prints a beautiful, colored CLI report with Risk Scores and Severity levels.
    """
    total = len(results)
    malicious_count = sum(1 for r in results if r["verdict"] == "MALICIOUS")
    suspicious_count = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    safe_count = sum(1 for r in results if r["verdict"] == "SAFE")
    
    table = Table(title="🛡️ ModelSentry Scan Results", expand=True)
    table.add_column("File Path", style="cyan", no_wrap=False)
    table.add_column("Type", style="magenta", width=12)
    table.add_column("Risk / Severity", width=16)
    table.add_column("Verdict", width=12)
    table.add_column("Details & Security Findings", style="white")
    
    for r in results:
        verdict = r["verdict"]
        risk_score = r.get("risk_score", 0.0)
        severity = r.get("severity", "SAFE")
        
        if verdict == "MALICIOUS":
            verdict_str = "[bold red]MALICIOUS[/bold red]"
            sev_str = f"[bold red]{severity} ({risk_score}/10)[/bold red]"
        elif verdict == "SUSPICIOUS":
            verdict_str = "[bold yellow]SUSPICIOUS[/bold yellow]"
            sev_str = f"[bold yellow]{severity} ({risk_score}/10)[/bold yellow]"
        else:
            verdict_str = "[bold green]SAFE[/bold green]"
            sev_str = f"[bold green]{severity} ({risk_score}/10)[/bold green]"
            
        reasons_str = "\n".join(f"- {reason}" for reason in r["reasons"])
        table.add_row(r["filepath"], r["file_type"], sev_str, verdict_str, reasons_str)
        
    console.print(table)
    console.print("\n")
    
    summary_text = (
        f"[bold]Scan Summary:[/bold]\n"
        f"- Total Files Scanned: {total}\n"
        f"- [bold green]Safe[/bold green]: {safe_count}\n"
        f"- [bold yellow]Suspicious[/bold yellow]: {suspicious_count}\n"
        f"- [bold red]Malicious[/bold red]: {malicious_count}\n"
    )
    
    if malicious_count > 0:
        panel_color = "red"
        title = "[CRITICAL] SECURITY ALERT - MALICIOUS MODELS DETECTED"
    elif suspicious_count > 0:
        panel_color = "yellow"
        title = "[WARNING] SUSPICIOUS METADATA / PAYLOADS DETECTED"
    else:
        panel_color = "green"
        title = "[OK] SCAN PASSED - ALL MODELS SAFE"
        
    console.print(Panel(summary_text, title=title, border_style=panel_color))

def export_sarif_report(results, output_path):
    """
    Exports scan results as OASIS SARIF v2.1.0 JSON format for GitHub Security integration.
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ModelSentry",
                        "informationUri": "https://github.com/ShauryaArvind/ModelSentry",
                        "semanticVersion": "2.0.0",
                        "rules": [
                            {
                                "id": "MS001",
                                "name": "ArbitraryCodeExecution",
                                "shortDescription": {"text": "Arbitrary python code execution vector detected in model artifact"}
                            },
                            {
                                "id": "MS002",
                                "name": "SuspiciousPayloadOrAppendedData",
                                "shortDescription": {"text": "Suspicious payload or appended bytes outside model metadata boundaries"}
                            }
                        ]
                    }
                },
                "results": []
            }
        ]
    }
    
    for r in results:
        if r["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            rule_id = "MS001" if r["verdict"] == "MALICIOUS" else "MS002"
            level = "error" if r["verdict"] == "MALICIOUS" else "warning"
            sarif["runs"][0]["results"].append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"ModelSentry finding for {r['filepath']}: " + "; ".join(r["reasons"])},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r["filepath"]}
                        }
                    }
                ]
            })
            
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)
    console.print(f"[bold green]SARIF v2.1.0 security report exported to:[/bold green] {output_path}")

def export_report(results, output_path):
    """
    Exports scan results as a Markdown or interactive dark-mode HTML audit report.
    """
    total = len(results)
    malicious = sum(1 for r in results if r["verdict"] == "MALICIOUS")
    suspicious = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    safe = sum(1 for r in results if r["verdict"] == "SAFE")
    
    if output_path.endswith('.html') or output_path.endswith('.htm'):
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ModelSentry Security Audit Dashboard</title>
    <style>
        :root {{ --bg: #0b0f19; --card: #151c2c; --border: #232d42; --text: #f1f5f9; --sub: #94a3b8; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 40px; background: var(--bg); color: var(--text); }}
        h1 {{ color: #38bdf8; font-weight: 700; display: flex; align-items: center; gap: 10px; margin-top: 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: var(--card); padding: 20px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }}
        .card h3 {{ margin: 0 0 10px 0; color: var(--sub); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .card .val {{ font-size: 2.2rem; font-weight: bold; }}
        .filter-bar {{ margin-bottom: 20px; display: flex; gap: 10px; }}
        .btn {{ background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.9rem; transition: all 0.2s; }}
        .btn:hover {{ border-color: #38bdf8; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }}
        th, td {{ padding: 14px 18px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #1a2336; color: var(--sub); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; display: inline-block; }}
        .SAFE {{ background: rgba(74, 222, 128, 0.15); color: #4ade80; border: 1px solid rgba(74, 222, 128, 0.3); }}
        .SUSPICIOUS {{ background: rgba(250, 204, 21, 0.15); color: #facc15; border: 1px solid rgba(250, 204, 21, 0.3); }}
        .MALICIOUS {{ background: rgba(248, 113, 113, 0.15); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.3); }}
        code {{ background: #0b0f19; padding: 3px 8px; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.85rem; color: #e2e8f0; }}
    </style>
</head>
<body>
    <h1>🛡️ ModelSentry Security Audit Dashboard</h1>
    <div class="summary">
        <div class="card"><h3>Total Models</h3><div class="val">{total}</div></div>
        <div class="card"><h3>Safe</h3><div class="val" style="color:#4ade80">{safe}</div></div>
        <div class="card"><h3>Suspicious</h3><div class="val" style="color:#facc15">{suspicious}</div></div>
        <div class="card"><h3>Malicious</h3><div class="val" style="color:#f87171">{malicious}</div></div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>File Path</th>
                <th>Format</th>
                <th>Risk Score</th>
                <th>Verdict</th>
                <th>Security Findings</th>
            </tr>
        </thead>
        <tbody>
"""
        for r in results:
            reasons = "<br>".join(r['reasons'])
            score = r.get("risk_score", 0.0)
            sev = r.get("severity", "SAFE")
            html_content += f"""            <tr>
                <td><code>{r['filepath']}</code></td>
                <td>{r['file_type']}</td>
                <td><strong>{score} / 10</strong> ({sev})</td>
                <td><span class="badge {r['verdict']}">{r['verdict']}</span></td>
                <td>{reasons}</td>
            </tr>\n"""
        html_content += """        </tbody>
    </table>
</body>
</html>"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    else:
        md_content = f"# 🛡️ ModelSentry Security Audit Report\n\n"
        md_content += f"## Scan Summary\n"
        md_content += f"- **Total Models Scanned**: {total}\n"
        md_content += f"- **SAFE**: {safe}\n"
        md_content += f"- **SUSPICIOUS**: {suspicious}\n"
        md_content += f"- **MALICIOUS**: {malicious}\n\n"
        md_content += f"## Detailed Security Findings\n\n"
        md_content += f"| File Path | Format | Risk Score | Verdict | Security Findings |\n"
        md_content += f"|---|---|---|---|---|\n"
        for r in results:
            reasons = "<br>".join(r['reasons'])
            score = r.get("risk_score", 0.0)
            md_content += f"| `{r['filepath']}` | {r['file_type']} | {score} / 10 | **{r['verdict']}** | {reasons} |\n"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
            
    console.print(f"[bold green]Security report exported to:[/bold green] {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="ModelSentry - Advanced Static Malware Scanner for AI Model Files (.pkl, .pt, .h5, .safetensors, .gguf, .onnx, .npy, .npz)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan local file or directory")
    scan_parser.add_argument("path", help="Path to local file or directory to scan")
    scan_parser.add_argument("-r", "--recursive", action="store_true", help="Scan subdirectories recursively")
    scan_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    scan_parser.add_argument("--sarif", help="Path to export SARIF v2.1.0 JSON report for GitHub Security")
    scan_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    scan_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    scan_parser.add_argument("--ignore-file", help="Path to custom ignore rules file (.modelsentryignore)")
    scan_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    scan_parser.add_argument("--threads", type=int, default=4, help="Number of worker threads for parallel scanning")
    scan_parser.add_argument("--config", help="Path to custom config file (.modelsentryrc or modelsentry.json)")
    
    # scan-url command
    url_parser = subparsers.add_parser("scan-url", help="Download and scan a model from a remote URL")
    url_parser.add_argument("url", help="URL of the model file")
    url_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    url_parser.add_argument("--sarif", help="Path to export SARIF v2.1.0 JSON report")
    url_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    url_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    url_parser.add_argument("--ignore-file", help="Path to custom ignore rules file")
    url_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    
    # scan-urls batch command
    urls_parser = subparsers.add_parser("scan-urls", help="Scan multiple URLs from a text file (one URL per line)")
    urls_parser.add_argument("file", help="Path to text file containing list of URLs")
    urls_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    urls_parser.add_argument("--sarif", help="Path to export SARIF v2.1.0 JSON report")
    urls_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    urls_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    urls_parser.add_argument("--ignore-file", help="Path to custom ignore rules file")
    urls_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    urls_parser.add_argument("--threads", type=int, default=4, help="Number of concurrent worker threads")

    # scan-hf command
    hf_parser = subparsers.add_parser("scan-hf", help="Scan remote model weights inside a Hugging Face repository")
    hf_parser.add_argument("repo_id", help="Hugging Face model repository ID (e.g. 'gpt2' or 'meta-llama/Llama-2-7b')")
    hf_parser.add_argument("--revision", default="main", help="Git branch or revision tag (default: 'main')")
    hf_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    hf_parser.add_argument("--sarif", help="Path to export SARIF v2.1.0 JSON report")
    hf_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    hf_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    hf_parser.add_argument("--ignore-file", help="Path to custom ignore rules file")
    hf_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    hf_parser.add_argument("--threads", type=int, default=4, help="Number of concurrent worker threads")

    # init-hook command
    hook_parser = subparsers.add_parser("init-hook", help="Install a Git pre-commit hook into .git/hooks/pre-commit")
    hook_parser.add_argument("--force", action="store_true", help="Overwrite existing pre-commit hook file if present")
    
    args = parser.parse_args()
    
    # Handle init-hook standalone command
    if args.command == "init-hook":
        success = init_pre_commit_hook(force=args.force)
        sys.exit(0 if success else 1)
    
    # Load config file
    config = load_config_file(getattr(args, "config", None))
    
    blocklist_path = getattr(args, "blocklist", None) or config.get("blocklist")
    allowlist_path = getattr(args, "allowlist", None) or config.get("allowlist")
    ignore_path = getattr(args, "ignore_file", None) or config.get("ignore_file")
    
    custom_blocklist = load_custom_rules_file(blocklist_path)
    custom_allowlist = load_custom_rules_file(allowlist_path)
    
    results = []
    
    if args.command == "scan":
        files = get_all_files(args.path, recursive=args.recursive)
        if not files:
            console.print(f"[bold red]Error:[/bold red] No files found at '{args.path}' to scan.")
            sys.exit(1)
            
        threads = getattr(args, "threads", 4)
        if len(files) > 1 and threads > 1:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_file = {
                    executor.submit(scan_file, f, custom_blocklist, custom_allowlist, ignore_file=ignore_path): f 
                    for f in files
                }
                for future in as_completed(future_to_file):
                    results.append(future.result())
        else:
            for filepath in files:
                results.append(scan_file(filepath, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist, ignore_file=ignore_path))
            
    elif args.command == "scan-url":
        res = handle_url_scan(args.url, is_json=args.json, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist, ignore_file=ignore_path)
        results.append(res)
        
    elif args.command == "scan-urls":
        if not os.path.exists(args.file):
            console.print(f"[bold red]Error:[/bold red] URL list file '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
        threads = getattr(args, "threads", 4)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {
                executor.submit(handle_url_scan, u, is_json=args.json, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist, ignore_file=ignore_path): u
                for u in urls
            }
            for future in as_completed(future_to_url):
                results.append(future.result())
                
    elif args.command == "scan-hf":
        threads = getattr(args, "threads", 4)
        results = handle_hf_scan(
            args.repo_id,
            revision=args.revision,
            is_json=args.json,
            custom_blocklist=custom_blocklist,
            custom_allowlist=custom_allowlist,
            ignore_file=ignore_path,
            threads=threads
        )
        
    # Presentation
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_rich_report(results)
        
    if getattr(args, "export_report", None):
        export_report(results, args.export_report)
        
    if getattr(args, "sarif", None):
        export_sarif_report(results, args.sarif)
        
    any_malicious = any(r["verdict"] == "MALICIOUS" for r in results)
    sys.exit(1 if any_malicious else 0)

if __name__ == "__main__":
    main()
