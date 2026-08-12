import os
import sys
import json
import argparse
import urllib.request
import tempfile
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner import scan_file

console = Console()

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
            # Skip common non-project directories
            dirs[:] = [d for d in dirs if d not in ('.git', '.venv', 'venv', '__pycache__', '.pytest_cache', '.agents', '.antigravity-ide')]
            for filename in filenames:
                files.append(os.path.join(root, filename))
            if not recursive:
                break
    return files

def handle_url_scan(url, is_json=False):
    """
    Downloads a file to a temporary location and scans it.
    """
    if not is_json:
        console.print(f"[bold blue]Downloading file from URL:[/bold blue] {url}")
        
    try:
        # Create a temp file with the same extension if possible
        ext = os.path.splitext(url.split('?')[0])[1]
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as temp_file:
            temp_path = temp_file.name
            
        # Download with a progress spinner
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
            
        result = scan_file(temp_path)
        # Fix the filename in results to the original URL
        result["filepath"] = url
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        return result
    except Exception as e:
        return {
            "filepath": url,
            "file_type": "none",
            "verdict": "SUSPICIOUS",
            "reasons": [f"Failed to download/scan URL: {str(e)}"],
            "details": {}
        }

def print_rich_report(results):
    """
    Prints a beautiful, colored CLI report.
    """
    total = len(results)
    malicious_count = sum(1 for r in results if r["verdict"] == "MALICIOUS")
    suspicious_count = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    safe_count = sum(1 for r in results if r["verdict"] == "SAFE")
    
    # Table of details
    table = Table(title="ModelSentry Scan Results", expand=True)
    table.add_column("File Path", style="cyan", no_wrap=False)
    table.add_column("Type", style="magenta", width=12)
    table.add_column("SHA-256", style="dim green", width=14)
    table.add_column("Verdict", width=12)
    table.add_column("Details/Reasons", style="white")
    
    for r in results:
        verdict = r["verdict"]
        if verdict == "MALICIOUS":
            verdict_str = "[bold red]MALICIOUS[/bold red]"
        elif verdict == "SUSPICIOUS":
            verdict_str = "[bold yellow]SUSPICIOUS[/bold yellow]"
        else:
            verdict_str = "[bold green]SAFE[/bold green]"
            
        sha_short = r.get("sha256", "N/A")[:12] if r.get("sha256") != "N/A" else "N/A"
        reasons_str = "\n".join(f"- {reason}" for reason in r["reasons"])
        table.add_row(r["filepath"], r["file_type"], sha_short, verdict_str, reasons_str)
        
    console.print(table)
    console.print("\n")
    
    # Summary card
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
        title = "[WARNING] SUSPICIOUS METADATA DETECTED"
    else:
        panel_color = "green"
        title = "[OK] SCAN PASSED - ALL MODELS SAFE"
        
    console.print(Panel(summary_text, title=title, border_style=panel_color))

def export_report(results, output_path):
    """
    Exports scan results as a Markdown or HTML audit report.
    """
    total = len(results)
    malicious = sum(1 for r in results if r["verdict"] == "MALICIOUS")
    suspicious = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    safe = sum(1 for r in results if r["verdict"] == "SAFE")
    
    if output_path.endswith('.html') or output_path.endswith('.htm'):
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ModelSentry Audit Report</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .summary {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #334155; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #334155; color: #f1f5f9; }}
        .SAFE {{ color: #4ade80; font-weight: bold; }}
        .SUSPICIOUS {{ color: #facc15; font-weight: bold; }}
        .MALICIOUS {{ color: #f87171; font-weight: bold; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <h1>ModelSentry Security Audit Report</h1>
    <div class="summary">
        <h3>Scan Overview</h3>
        <p>Total Scanned: <strong>{total}</strong> | Safe: <span class="SAFE">{safe}</span> | Suspicious: <span class="SUSPICIOUS">{suspicious}</span> | Malicious: <span class="MALICIOUS">{malicious}</span></p>
    </div>
    <table>
        <thead>
            <tr>
                <th>File Path</th>
                <th>Type</th>
                <th>SHA-256</th>
                <th>Verdict</th>
                <th>Reasons / Findings</th>
            </tr>
        </thead>
        <tbody>
"""
        for r in results:
            sha = r.get('sha256', 'N/A')
            reasons = "<br>".join(r['reasons'])
            html_content += f"""            <tr>
                <td><code>{r['filepath']}</code></td>
                <td>{r['file_type']}</td>
                <td><code>{sha[:16]}...</code></td>
                <td class="{r['verdict']}">{r['verdict']}</td>
                <td>{reasons}</td>
            </tr>\n"""
        html_content += """        </tbody>
    </table>
</body>
</html>"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    else:
        md_content = f"# ModelSentry Security Audit Report\n\n"
        md_content += f"## Scan Summary\n"
        md_content += f"- **Total Scanned**: {total}\n"
        md_content += f"- **SAFE**: {safe}\n"
        md_content += f"- **SUSPICIOUS**: {suspicious}\n"
        md_content += f"- **MALICIOUS**: {malicious}\n\n"
        md_content += f"## Detailed Findings\n\n"
        md_content += f"| File Path | Format | SHA-256 Digest | Verdict | Reasons / Findings |\n"
        md_content += f"|---|---|---|---|---|\n"
        for r in results:
            sha = r.get('sha256', 'N/A')
            reasons = "<br>".join(r['reasons'])
            md_content += f"| `{r['filepath']}` | {r['file_type']} | `{sha[:12]}...` | **{r['verdict']}** | {reasons} |\n"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
            
    console.print(f"[bold green]Security report successfully exported to:[/bold green] {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="ModelSentry - Static Malware Scanner for AI Model Files (.pkl, .pt, .h5, .safetensors)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan local file or directory")
    scan_parser.add_argument("path", help="Path to local file or directory to scan")
    scan_parser.add_argument("-r", "--recursive", action="store_true", help="Scan subdirectories recursively")
    scan_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    scan_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    scan_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    scan_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    
    # scan-url command
    url_parser = subparsers.add_parser("scan-url", help="Download and scan a model from a remote URL")
    url_parser.add_argument("url", help="URL of the model file")
    url_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    url_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    url_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    url_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    
    # scan-urls batch command
    urls_parser = subparsers.add_parser("scan-urls", help="Scan multiple URLs from a text file (one URL per line)")
    urls_parser.add_argument("file", help="Path to text file containing list of URLs")
    urls_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    urls_parser.add_argument("--blocklist", help="Path to custom blocklist rules file")
    urls_parser.add_argument("--allowlist", help="Path to custom allowlist rules file")
    urls_parser.add_argument("--export-report", help="Export scan report to a file (.md or .html)")
    
    args = parser.parse_args()
    
    results = []
    
    from scanner import load_custom_rules_file
    custom_blocklist = load_custom_rules_file(getattr(args, "blocklist", None))
    custom_allowlist = load_custom_rules_file(getattr(args, "allowlist", None))
    
    if args.command == "scan":
        files = get_all_files(args.path, recursive=args.recursive)
        if not files:
            console.print(f"[bold red]Error:[/bold red] No files found at '{args.path}' to scan.")
            sys.exit(1)
            
        for filepath in files:
            results.append(scan_file(filepath, custom_blocklist=custom_blocklist, custom_allowlist=custom_allowlist))
            
    elif args.command == "scan-url":
        res = handle_url_scan(args.url, is_json=args.json)
        results.append(res)
        
    elif args.command == "scan-urls":
        if not os.path.exists(args.file):
            console.print(f"[bold red]Error:[/bold red] URL list file '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for u in urls:
            results.append(handle_url_scan(u, is_json=args.json))
        
    # Output presentation
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_rich_report(results)
        
    if getattr(args, "export_report", None):
        export_report(results, args.export_report)
        
    # Set exit code: 1 if any malicious files detected
    any_malicious = any(r["verdict"] == "MALICIOUS" for r in results)
    if any_malicious:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
