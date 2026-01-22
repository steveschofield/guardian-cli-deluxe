"""
guardian workflow - Run predefined workflows
"""

import typer
import asyncio
import yaml
from rich.console import Console
from rich.table import Table
from pathlib import Path

from utils.helpers import load_config
from utils.session_paths import resolve_session_file, find_latest_session_file
from core.memory import PentestMemory
from core.workflow import WorkflowEngine

console = Console()


def workflow_command(
    action: str = typer.Argument(..., help="Action: 'run' or 'list'"),
    name: str = typer.Option(None, "--name", "-n", help="Workflow name (recon, web, network, autonomous)"),
    target: str = typer.Option(None, "--target", "-t", help="Target for the workflow"),
    resume: str = typer.Option(None, "--resume", help="Resume from a session id or path (use 'latest' for newest)"),
    config_file: Path = typer.Option(
        "config/guardian.yaml",
        "--config",
        "-c",
        help="Configuration file path"
    )
):
    """
    Run or list penetration testing workflows
    
    Available workflows:
    - recon: Reconnaissance workflow
    - web: Web application pentest
    - network: Network infrastructure pentest
    - autonomous: AI-driven autonomous testing
    """
    if action == "list":
        _list_workflows()
        return
    
    if action == "run":
        if not name:
            console.print("[bold red]Error:[/bold red] --name is required for 'run' action")
            raise typer.Exit(1)

        if not target and not resume:
            console.print("[bold red]Error:[/bold red] --target is required for 'run' action unless --resume is used")
            raise typer.Exit(1)

        _run_workflow(name, target, config_file, resume)
    else:
        console.print(f"[bold red]Error:[/bold red] Unknown action: {action}")
        raise typer.Exit(1)


def _list_workflows():
    """List available workflows"""
    table = Table(title="Available Workflows")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")

    workflows_dir = Path(__file__).resolve().parent.parent.parent / "workflows"

    aliases = {
        "recon": "recon",
        "web": "web_pentest",
        "network": "network_pentest",
        "autonomous": "autonomous",
    }

    workflows: dict[str, str] = {}
    for name, target in aliases.items():
        description = "Workflow"
        if workflows_dir.exists():
            path = workflows_dir / f"{target}.yaml"
            if path.exists():
                try:
                    data = yaml.safe_load(path.read_text()) or {}
                    description = data.get("description") or description
                except Exception:
                    pass
        if target != name:
            description = f"{description} (workflow: {target})"
        workflows[name] = description

    if workflows_dir.exists():
        for path in sorted(workflows_dir.glob("*.yaml")):
            name = path.stem
            if name in workflows or name in aliases.values():
                continue
            description = "Custom workflow"
            try:
                data = yaml.safe_load(path.read_text()) or {}
                description = data.get("description") or description
            except Exception:
                pass
            workflows[name] = description

    for name, description in workflows.items():
        table.add_row(name, description)

    console.print(table)


def _run_workflow(name: str, target: str, config_file: Path, resume: str = None):
    """Run a workflow"""
    try:
        config = load_config(str(config_file))
        if not config:
            console.print("[bold red]Error:[/bold red] Failed to load configuration")
            raise typer.Exit(1)
        
        memory = None
        if resume:
            if resume == "latest":
                session_file = find_latest_session_file(config)
            else:
                resume_path = Path(resume)
                if resume_path.exists():
                    session_file = resume_path
                else:
                    session_file = resolve_session_file(config, resume)
            if not session_file or not session_file.exists():
                console.print(f"[bold red]Error:[/bold red] Session not found for resume: {resume}")
                raise typer.Exit(1)

            memory = PentestMemory(target="")
            if not memory.load_state(session_file):
                console.print(f"[bold red]Error:[/bold red] Failed to load session state: {session_file}")
                raise typer.Exit(1)

            if target and target != memory.target:
                console.print(
                    f"[yellow]Warning:[/yellow] --target differs from session target; using {memory.target}"
                )
            target = memory.target

        if resume:
            console.print(f"[bold cyan]🔄 Resuming {name} workflow on {target}[/bold cyan]\n")
        else:
            console.print(f"[bold cyan]🚀 Running {name} workflow on {target}[/bold cyan]\n")

        engine = WorkflowEngine(config, target, memory=memory)
        
        if name == "autonomous":
            results = asyncio.run(engine.run_autonomous())
        else:
            results = asyncio.run(engine.run_workflow(name))
        
        console.print(f"\n[bold green]✓ Workflow completed![/bold green]")
        console.print(f"Findings: [cyan]{results['findings']}[/cyan]")
        console.print(f"Session: [cyan]{results['session_id']}[/cyan]")
        
    except Exception as e:
        import traceback
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        console.print(f"[dim]Traceback: {traceback.format_exc()}[/dim]")
        raise typer.Exit(1)
