#!/usr/bin/env python3
"""
MiniWebScan v1.0
A lightweight web vulnerability scanner for security testing your own sites.
Author: sdev
License: MIT
"""

import requests
import argparse
import concurrent.futures
import urllib3
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy"
]

BANNER = """
[bold cyan]
███╗ ███╗██╗███╗ ██╗██╗ ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗ ██╗
████╗ ████║██║████╗ ██║██║ ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║
██╔████╔██║██║██╔██╗ ██║██║ █╗ ██║█████╗ ██████╔╝███████╗██║ ███████║██╔██╗ ██║
██║╚██╔╝██║██║██║╚██╗██║██║███╗██║██╔══╝ ██╔══██╗╚════██║██║ ██╔══██║██║╚██╗██║
██║ ╚═╝ ██║██║██║ ╚████║╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║ ██║██║ ╚████║
╚═╝ ╚═╝╚═╝╚═╝ ╚═══╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝ ╚═╝╚═╝ ╚═══╝
[/bold cyan]
[dim]MiniWebScan v1.0 | Author: sdev | Use only on authorized targets[/dim]
"""

def check_headers(url, verify_ssl):
    try:
        r = requests.get(url, timeout=8, verify=verify_ssl, headers={"User-Agent": "MiniWebScan/1.0"})
        headers = r.headers
        found = []
        missing = []

        for h in SECURITY_HEADERS:
            if h in headers:
                found.append((h, headers[h]))
            else:
                missing.append(h)

        return found, missing, r.status_code, r.elapsed.total_seconds()
    except requests.exceptions.SSLError:
        return None, None, "SSL Error", None
    except requests.exceptions.ConnectionError:
        return None, None, "Connection Failed", None
    except Exception as e:
        return None, None, f"Error: {e}", None

def brute_directory(url, path, verify_ssl):
    target = urljoin(url, path)
    try:
        r = requests.get(target, timeout=4, verify=verify_ssl,
                        headers={"User-Agent": "MiniWebScan/1.0"})
        if r.status_code in [200, 301, 302, 403, 401]:
            return (path, r.status_code, len(r.content))
    except requests.exceptions.RequestException:
        # Mengabaikan error network individual agar proses scan tetap lanjut
        pass
    return None

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="MiniWebScan - Web vulnerability scanner for authorized testing",
        epilog="Example: python miniwebscan.py https://localhost:8443 --insecure"
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Wordlist file path")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads for brute force")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("-o", "--output", help="Save results to file")
    args = parser.parse_args()

    verify_ssl = not args.insecure

    # Memastikan URL berakhiran slash agar urljoin tidak memotong path dasar
    target_url = args.url
    if not target_url.endswith("/"):
        target_url += "/"

    console.print(f"[bold cyan]Target:[/bold cyan] {target_url}")
    console.print(f"[bold cyan]SSL Verify:[/bold cyan] {verify_ssl}")
    console.print(f"[bold cyan]Threads:[/bold cyan] {args.threads}\n")

    # 1. Security Headers Check
    console.print(Panel("[bold yellow]Phase 1: Security Headers Analysis[/bold yellow]"))
    found, missing, status, time_taken = check_headers(target_url, verify_ssl)

    if found is not None:
        table = Table(title=f"Security Headers | Status: {status} | Time: {time_taken:.2f}s")
        table.add_column("Header", style="cyan", width=25)
        table.add_column("Status", style="green", width=10)
        table.add_column("Value", style="white")

        for h, v in found:
            table.add_row(h, "✓", v[:70])
        for h in missing:
            table.add_row(h, "[red]✗ Missing[/red]", "-")

        console.print(table)

        score = len(found) / len(SECURITY_HEADERS) * 100
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        console.print(f"\n[bold]Security Score: [{score_color}]{score:.0f}/100[/{score_color}][/bold]")
    else:
        console.print(f"[red]Failed: {status}[/red]")
        sys.exit(1)

    # 2. Directory Brute Force
    console.print(Panel("\n[bold yellow]Phase 2: Directory Brute Force[/bold yellow]"))
    try:
        with open(args.wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist {args.wordlist} not found.[/red]")
        return

    found_paths = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(lambda p: brute_directory(target_url, p, verify_ssl), paths)
        for res in results:
            if res:
                found_paths.append(res)
                color = "green" if res[1] == 200 else "yellow"
                # Perbaikan Markup Error menggunakan penutup tag yang valid '[/]'
                console.print(f"[{color}][{res[1]}][/] /{res[0]} - {res[2]} bytes")

    # 3. Summary & Save
    console.print(Panel(f"\n[bold green]Scan Complete![/bold green]\nFound {len(found_paths)} accessible paths"))

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"MiniWebScan Results for {target_url}\n")
            f.write("="*50 + "\n")
            for path, code, size in found_paths:
                f.write(f"[{code}] /{path} - {size} bytes\n")
        console.print(f"[dim]Results saved to {args.output}[/dim]")

    console.print("\n[dim]⚠️ Only test on sites you own or have explicit permission to test.[/dim]")

if __name__ == "__main__":
    main()
