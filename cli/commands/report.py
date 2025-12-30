"""
guardian report - Generate reports
"""

import typer
from rich.console import Console
from pathlib import Path

console = Console()


def report_command(
    session_id: str = typer.Option(..., "--session", "-s", help="Session ID to generate report for"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format (markdown, html, json)"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    config_file: Path = typer.Option(
        "config/guardian.yaml",
        "--config",
        "-c",
        help="Configuration file path"
    )
):
    """
    Generate penetration testing report
    
    Creates a professional report from session data.
    """
    import asyncio
    from pathlib import Path
    from utils.helpers import load_config
    from core.memory import PentestMemory
    from core.reporter_agent import ReporterAgent
    from ai.provider_factory import get_llm_client
    
    console.print(f"[bold cyan]📄 Generating Report: {session_id}[/bold cyan]\n")
    
    # Load session
    session_file = Path(f"./reports/session_{session_id}.json")
    if not session_file.exists():
        console.print(f"[red]Session not found: {session_file}[/red]")
        raise typer.Exit(1)
    
    try:
        # Load configuration and session
        config = load_config(str(config_file))
        memory = PentestMemory(target="")
        memory.load_state(session_file)
        
        # Initialize Reporter Agent
        llm_client = get_llm_client(config)
        reporter = ReporterAgent(config, llm_client, memory)
        
        # Generate markdown and html
        outputs = []
        for fmt, ext in (("markdown", "md"), ("html", "html")):
            console.print(f"Generating {fmt} report...")
            report = asyncio.run(reporter.execute(format=fmt))

            if output:
                base = output.with_suffix("")
                out_path = base.with_suffix(f".{ext}")
            else:
                out_path = Path(f"./reports/report_{session_id}.{ext}")

            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(report["content"])
            outputs.append((fmt, out_path))
        
        console.print(f"\n[green]✓ Reports generated successfully![/green]")
        for fmt, path in outputs:
            console.print(f"{fmt.upper()}: [cyan]{path}[/cyan]")
        console.print(f"Findings: [cyan]{len(memory.findings)}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise typer.Exit(1)
