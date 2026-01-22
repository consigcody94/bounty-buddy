import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import print as rprint
import os
import sys
from dotenv import load_dotenv

# Initialize Typer app and Rich console
app = typer.Typer(help="Bounty Buddy - The All-In-One Bug Bounty Toolkit")
console = Console()
state = {"verbose": False}

@app.callback()
def main(verbose: bool = False):
    """
    Bounty Buddy: Automated Reconnaissance & Vulnerability Scanning.
    """
    if verbose:
        state["verbose"] = True
        console.print("[dim]Verbose mode enabled[/dim]")

@app.command()
def setup():
    """
    Configure API keys and environment.
    """
    console.print(Panel.fit("🔧 Bounty Buddy Setup", style="bold cyan"))
    
    shodan_key = Prompt.ask("Enter your Shodan API Key (leave empty to skip)", password=True)
    
    env_content = ""
    if shodan_key:
        env_content += f"SHODAN_API_KEY={shodan_key}\n"
    
    if env_content:
        with open(".env", "w") as f:
            f.write(env_content)
        console.print("[green]✓ Configuration saved to .env[/green]")
    else:
        console.print("[yellow]⚠ No keys provided. Some features may be limited.[/yellow]")

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or IP"),
    shodan: bool = typer.Option(False, "--shodan", "-s", help="Enable Shodan scanning"),
    passive: bool = typer.Option(True, help="Use passive enumeration only"),
):
    """
    Start a reconnaissance scan on a target.
    """
    console.print(Panel(f"🎯 Target: [bold green]{target}[/bold green]", title="Starting Scan", border_style="green"))
    
    # Placeholder for actual logic
    if shodan:
        from bountybuddy.scanners.shodan_scanner import scan_shodan
        scan_shodan(target, console)
    
    if passive:
        console.print("[blue]ℹ Performing passive reconnaissance...[/blue]")
        # TODO: Implement passive recon manager

@app.command()
def research():
    """
    View latest bug bounty research and tips.
    """
    # TODO: Read from BUG_BOUNTY_RESEARCH.md
    console.print("[cyan]📚 Displaying knowledge base...[/cyan]")
    research_file = "BUG_BOUNTY_RESEARCH.md"
    if os.path.exists(research_file):
        from rich.markdown import Markdown
        with open(research_file, "r") as f:
            md = Markdown(f.read())
        console.print(md)
    else:
        console.print("[red]❌ Research file not found![/red]")

if __name__ == "__main__":
    app()
