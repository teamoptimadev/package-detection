import argparse
import sys
import os
from pathlib import Path
from rich.console import Console # type: ignore
from rich.panel import Panel # type: ignore
from rich.table import Table # type: ignore
from rich.progress import Progress, SpinnerColumn, TextColumn # type: ignore
from detector.engine import DetectionEngine # type: ignore

console = Console()

def display_results(result):
    """Format and display analysis results in the terminal."""
    if "error" in result:
        console.print(f"[bold red]ERROR: {result['error']}[/bold red]")
        sys.exit(1)

    package_name = result['package_name']
    registry = result['registry']
    behaviors = result['behaviors']
    behavior_desc = result['behavior_description']
    rag_match = result['rag_match']
    analysis = result['analysis']

    # Header Panel
    console.print(Panel(
        f"[bold cyan]Package:[/] {package_name} ([dim]{registry}[/])\n"
        f"[bold cyan]Result:[/] [bold {get_verdict_color(analysis['verdict'])}]{analysis['verdict']}[/]"
        f"\n[bold cyan]Risk Score:[/] {analysis['score']}/100",
        title="[bold white]Package Analysis Summary[/bold white]",
        border_style="bright_blue"
    ))

    # Behaviors Table
    table = Table(title="Detected Behavioral Indicators")
    table.add_column("Indicator", style="yellow")
    table.add_column("Type", style="magenta")
    
    for b in behaviors:
        if "SENSITIVE" in b or "SHELL" in b:
            table.add_row(b, "CRITICAL")
        elif "URL" in b or "NETWORK" in b or "ENV" in b:
            table.add_row(b, "SUSPICIOUS")
        else:
            table.add_row(b, "INFORMATIONAL")
    
    console.print(table)

    # RAG Match Panel
    if rag_match:
        console.print(Panel(
            f"[bold magenta]Topic:[/] {rag_match['pattern']['threat']} ([dim]Score: {int(rag_match['score']*100)}%[/])\n"
            f"[bold magenta]Match Context:[/] {rag_match['pattern']['pattern']}\n"
            f"[italic]{rag_match['pattern']['description']}[/]",
            title="[bold white]RAG Database Match[/bold white]",
            border_style="magenta"
        ))

    # AI Reasoning Panel
    console.print(Panel(
        f"[dim]{analysis['reasoning']}[/]\n\n"
        f"[bold]Confidence Information:[/] [green]{analysis['confidence']}[/]",
        title="[bold white]AI Logic & Reasoning[/bold white]",
        border_style="cyan"
    ))

def get_verdict_color(verdict):
    if verdict == "MALICIOUS": return "bright_red"
    if verdict == "SUSPICIOUS": return "orange1"
    return "bright_green"

def main():
    parser = argparse.ArgumentParser(description="Malicious Package Detection CLI")
    parser.add_argument("package_name", nargs='?', help="Package name to scan (legacy)")
    parser.add_argument("--registry", choices=["npm", "pypi"], default="npm", help="Package registry")
    parser.add_argument("--local", help="Path to local package directory for scanning")
    args = parser.parse_args()

    engine = DetectionEngine()

    if args.local:
        package_name = Path(args.local).name
        registry = "local"
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description=f"Scanning local directory '{args.local}'...", total=None)
            
            # Simulated engine.run for local
            extract_dir = Path(args.local)
            source_files = engine.downloader.get_source_files(extract_dir)
            all_tokens = []
            for file_path in source_files:
                tokens = engine.ast_parser.parse_file(file_path)
                all_tokens.extend(tokens)
            behaviors = engine.behavior_extractor.extract(all_tokens)
            behavior_description = engine.behavior_extractor.to_natural_language(behaviors)
            rag_results = engine.vector_db.search_similar(behavior_description, top_k=1)
            analysis_result = engine.analyzer.analyze(behaviors, rag_results)
            result = {
                "package_name": package_name,
                "registry": registry,
                "behaviors": behaviors,
                "behavior_description": behavior_description,
                "rag_match": rag_results[0] if rag_results else None,
                "analysis": analysis_result
            }
    elif args.package_name:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description=f"Scanning package '{args.package_name}'...", total=None)
            result = engine.run(args.package_name, args.registry)
    else:
        parser.print_help()
        sys.exit(1)

    display_results(result)

if __name__ == "__main__":
    main()
