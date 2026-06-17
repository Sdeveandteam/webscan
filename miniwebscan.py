#!/usr/bin/env python3
"""
MiniWebScan v1.2
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
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

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

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "'-alert(1)-'"
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "\\",
    " AND 1=1",
    " ORDER BY 1"
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "invalid query",
    "warning: mysql_",
    "pg_query(): query error",
    "oracle error",
    "sqlite3::query"
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
[dim]MiniWebScan v1.2 | Author: sdev | Use only on authorized targets[/dim]
"""

def check_headers(url, verify_ssl):
    try:
        r = requests.get(url, timeout=8, verify=verify_ssl, headers={"User-Agent": "MiniWebScan/1.2"})
        headers = r.headers
        found, missing = [], []

        for h in SECURITY_HEADERS:
            if h in headers:
                found.append((h, headers[h]))
            else:
                missing.append(h)

        return found, missing, r.status_code, r.elapsed.total_seconds()
    except Exception as e:
        return None, None, f"Error: {e}", None

def brute_directory(url, path, verify_ssl):
    target = urljoin(url, path)
    try:
        r = requests.get(target, timeout=4, verify=verify_ssl, headers={"User-Agent": "MiniWebScan/1.2"})
        if r.status_code in [200, 301, 302, 403, 401]:
            return (path, r.status_code, len(r.content))
    except:
        pass
    return None

def scan_parameter_bugs(url, verify_ssl):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    if not params:
        console.print("[yellow]![/yellow] Info: URL tidak memiliki parameter untuk diuji (contoh target ideal: [dim]page.php?id=1[/dim])")
        return []

    findings = []
    
    for param_name in params.keys():
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))
            
            try:
                r = requests.get(test_url, timeout=5, verify=verify_ssl, headers={"User-Agent": "MiniWebScan/1.2"})
                if payload in r.text:
                    findings.append(("XSS", param_name, payload, test_url))
                    break
            except:
                pass

        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            orig_val = params[param_name][0]
            test_params[param_name] = [f"{orig_val}{payload}"]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))
            
            try:
                r = requests.get(test_url, timeout=5, verify=verify_ssl, headers={"User-Agent": "MiniWebScan/1.2"})
                response_lower = r.text.lower()
                
                for sql_error in SQL_ERRORS:
                    if sql_error in response_lower:
                        findings.append(("SQLi (Error-Based)", param_name, payload, test_url))
                        break
                if any(sql_error in response_lower for sql_error in SQL_ERRORS):
                    break
            except:
                pass
                
    return findings

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="MiniWebScan - Web vulnerability scanner for authorized testing",
        epilog="Example: python miniwebscan.py 'https://example.com/search.php?q=test'"
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Wordlist file path")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads for brute force")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("-o", "--output", help="Save results to file")
    args = parser.parse_args()

    verify_ssl = not args.insecure
    target_url = args.url

    console.print(f"[bold cyan]Target:[/bold cyan] {target_url}")
    console.print(f"[bold cyan]SSL Verify:[/bold cyan] {verify_ssl}")
    console.print(f"[bold cyan]Threads:[/bold cyan] {args.threads}\n")

    # ================= PHASE 1: HEADERS =================
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

    # ================= PHASE 2: BRUTE FORCE =================
    console.print(Panel("\n[bold yellow]Phase 2: Directory Brute Force[/bold yellow]"))
    base_url = target_url if target_url.endswith("/") else target_url.rsplit('/', 1)[0] + '/'
    
    try:
        with open(args.wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist {args.wordlist} not found. Skipping Phase 2.[/red]")
        paths = []

    found_paths = []
    if paths:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            results = executor.map(lambda p: brute_directory(base_url, p, verify_ssl), paths)
            for res in results:
                if res:
                    found_paths.append(res)
                    color = "green" if res[1] == 200 else "yellow"
                    console.print(f"[{color}][{res[1]}][/] /{res[0]} - {res[2]} bytes")

    # ================= PHASE 3: VULN SCANNER =================
    console.print(Panel("\n[bold yellow]Phase 3: Parameter Vulnerability Scanner (XSS & SQLi)[/bold yellow]"))
    console.print("[dim]Analyzing parameters...[/dim]")
    vuln_findings = scan_parameter_bugs(target_url, verify_ssl)

    if vuln_findings:
        for vuln_type, param, payload, t_url in vuln_findings:
            console.print(f"[bold red][🔥 VULNERABLE][/bold red] [bold white]{vuln_type}[/bold white] ditemukan pada parameter: [bold cyan]{param}[/bold cyan]")
            console.print(f" -> Payload: {payload}")
            console.print(f" -> Test URL: [dim]{t_url}[/dim]\n")
    else:
        console.print("[green]✓[/green] Tidak ditemukan celah XSS atau Error-Based SQLi dasar pada parameter URL saat ini.")

    # ================= SUMMARY =================
    console.print(Panel(f"\n[bold green]Scan Complete![/bold green]\nFound {len(found_paths)} folders & {len(vuln_findings)} vulnerabilities."))

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"MiniWebScan Results for {target_url}\n")
            f.write("="*50 + "\n")
            f.write("[Directories]\n")
            for path, code, size in found_paths:
                f.write(f"[{code}] /{path} - {size} bytes\n")
            f.write("\n[Vulnerabilities]\n")
            for vuln_type, param, payload, t_url in vuln_findings:
                f.write(f"⚠️ {vuln_type} | Parameter: {param} | URL: {t_url}\n")
        console.print(f"[dim]Results saved to {args.output}[/dim]")

if __name__ == "__main__":
    main()
