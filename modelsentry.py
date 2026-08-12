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
            
        reasons_str = "\n".join(f"- {reason}" for reason in r["reasons"])
        table.add_row(r["filepath"], r["file_type"], verdict_str, reasons_str)
        
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
    
    # scan-url command
    url_parser = subparsers.add_parser("scan-url", help="Download and scan a model from a remote URL")
    url_parser.add_argument("url", help="URL of the model file")
    url_parser.add_argument("--json", action="store_true", help="Print output in JSON format")
    
    args = parser.parse_args()
    
    results = []
    
    if args.command == "scan":
        files = get_all_files(args.path, recursive=args.recursive)
        if not files:
            console.print(f"[bold red]Error:[/bold red] No files found at '{args.path}' to scan.")
            sys.exit(1)
            
        for filepath in files:
            results.append(scan_file(filepath))
            
    elif args.command == "scan-url":
        results.append(handle_url_scan(args.url, is_json=args.json))
        
    # Output presentation
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_rich_report(results)
        
    # Set exit code: 1 if any malicious files detected
    any_malicious = any(r["verdict"] == "MALICIOUS" for r in results)
    if any_malicious:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
