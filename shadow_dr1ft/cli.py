import sys
import json
import re
import asyncio
import typer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from shadow_dr1ft.extractor import scan_multiple_targets
from shadow_dr1ft.parser import load_openapi_spec
from shadow_dr1ft.diff_engine import analyze_drift

app = typer.Typer(help="shadow-dr1ft v2.0: High-Speed Deep API Drift & Shadow Endpoint Scanner")
console = Console()

def show_banner():
    banner_art = """[bold cyan]
   _____ __              __                  ____       ___ ____ __ 
  / ___// /_  ____ _____/ /___ _      __    / __ \\_____<  // __/ /_
  \\__ \\/ __ \\/ __ `/ __  / __ \\ | /| / /___/ / / / ___// // /_/ __/
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ /___/ /_/ / /   / // __/ /_  
/____/_/ /_/\\__,_/\\__,_/\\____/|__/|__/   /_____/_/   /_//_/  \\__/  
    [/bold cyan]"""
    
    info = (
        "[bold white]Tool:[/bold white] [bold green]shadow-dr1ft[/bold green] [bold yellow](v2.0.0 Pro - Async Deep Engine)[/bold yellow]\n"
        "[bold white]Author:[/bold white] [bold magenta]r!shu [ 0b1toUch!h4 ][/bold magenta]\n"
        "[bold white]Focus:[/bold white] [dim]Deep JS/Chunk Mining, Shadow API, Zombie Endpoint & Spec Drift[/dim]"
    )
    console.print(banner_art)
    console.print(Panel(info, border_style="cyan", expand=False))
    console.print()

def parse_headers(header_list: list[str]) -> dict:
    headers = {}
    if not header_list:
        return headers
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

def render_results_table(results: list[dict], show_target_col: bool = False):
    if not results:
        console.print("[bold green][✓] Scan complete. No API drift or hidden shadow endpoints detected![/bold green]")
        return

    table = Table(
        title="[bold cyan]shadow-dr1ft v2.0 :: Deep API Drift & Shadow Analysis[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on blue"
    )
    
    if show_target_col:
        table.add_column("Target Host", style="dim white", max_width=28)
    table.add_column("Drift / Status", style="bold", width=16)
    table.add_column("Method", justify="center", width=8)
    table.add_column("Endpoint Path & Hidden Params", style="cyan")
    table.add_column("Source JS/Chunk", style="dim")
    table.add_column("Risk Level", justify="center", width=14)

    for item in results:
        row = []
        if show_target_col:
            row.append(item.get("target", ""))
        row.extend([
            item["status"],
            item["method"],
            item["endpoint"],
            item["source"],
            item["risk"]
        ])
        table.add_row(*row)

    console.print(table)
    console.print(f"\n[bold green][+][/bold green] Total High-Value Anomalies Found: [bold white]{len(results)}[/bold white]\n")

@app.command()
def scan(
    url: str = typer.Option(None, "--url", "-u", help="Single target URL (e.g., https://example.com)"),
    url_list: str = typer.Option(None, "--list", "-l", help="File containing list of target URLs for mass scanning"),
    spec: str = typer.Option(None, "--spec", "-s", help="Path or URL to swagger.json / openapi.yaml"),
    header: list[str] = typer.Option(None, "--header", "-H", help="Custom HTTP headers (e.g., 'Authorization: Bearer xyz')"),
    concurrency: int = typer.Option(20, "--concurrency", "-c", help="Concurrent async workers for zero-lag scanning"),
    output: str = typer.Option(None, "--output", "-o", help="Save clean results to a JSON file")
):
    """Deeply scan single or mass targets (via -u, -l, or stdin pipe) for Shadow & Zombie APIs."""
    show_banner()
    headers = parse_headers(header)
    targets = []

    # ১. ইনপুট সংগ্রহ (Single URL, File List, অথবা Unix Stdin Pipe)
    if url:
        targets.append(url.strip())
    if url_list:
        list_path = Path(url_list)
        if not list_path.exists():
            console.print(f"[bold red][!] Target list file not found:[/bold red] {url_list}")
            raise typer.Exit(1)
        lines = [line.strip() for line in list_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        targets.extend(lines)
    if not sys.stdin.isatty():
        stdin_lines = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
        targets.extend(stdin_lines)

    # ডুপ্লিকেট রিমুভ এবং ভ্যালিডেশন
    targets = list(dict.fromkeys([t for t in targets if t.startswith(("http://", "https://"))]))

    if not targets:
        console.print("[bold red][!] No valid target URLs provided! Use -u https://target.com, -l urls.txt, or pipe via stdin.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold yellow][*][/bold yellow] Targets Loaded: [bold white]{len(targets)}[/bold white] | Async Workers: [bold cyan]{concurrency}[/bold cyan]")
    if spec:
        console.print(f"[bold yellow][*][/bold yellow] OpenAPI Spec: [underline]{spec}[/underline]")
    else:
        console.print("[bold yellow][!][/bold yellow] Mode: Deep JS & Chunk Discovery (No Spec provided)")
    console.print()

    # ২. Async Deep Crawl 실행
    with console.status(f"[bold cyan]Running high-speed deep JS & Webpack chunk analysis across {len(targets)} target(s)...[/bold cyan]", spinner="dots"):
        js_endpoints = asyncio.run(scan_multiple_targets(targets, headers, concurrency))
    
    console.print(f"[bold green][✓][/bold green] Deep Scan Finished! Extracted [bold white]{len(js_endpoints)}[/bold white] unique API routes.")

    # ৩. OpenAPI Spec পার্সিং
    spec_endpoints = []
    if spec:
        with console.status("[bold cyan]Parsing OpenAPI / Swagger specification...[/bold cyan]", spinner="dots"):
            spec_endpoints = load_openapi_spec(spec, headers)
        console.print(f"[bold green][✓][/bold green] Loaded [bold white]{len(spec_endpoints)}[/bold white] documented endpoints from spec.\n")
    else:
        console.print()

    # ৪. Differential Analysis ও টেবিল রেন্ডারিং
    findings = analyze_drift(js_endpoints, spec_endpoints)
    render_results_table(findings, show_target_col=(len(targets) > 1))

    # ৫. JSON এক্সপোর্ট
    if output and findings:
        clean_export = [
            {
                "target": f.get("target", ""),
                "status": re.sub(r'\[/?[^\]]+\]', '', f["status"]),
                "method": re.sub(r'\[/?[^\]]+\]', '', f["method"]),
                "endpoint": re.sub(r'\[/?[^\]]+\]', '', f["endpoint"]),
                "source": f["source"],
                "risk": re.sub(r'\[/?[^\]]+\]', '', f["risk"]),
            }
            for f in findings
        ]
        Path(output).write_text(json.dumps(clean_export, indent=2), encoding="utf-8")
        console.print(f"[bold green][✓][/bold green] Report saved to [underline]{output}[/underline]")

if __name__ == "__main__":
    app()
