import shodan
import os
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

def scan_shodan(target: str, console: Console):
    """
    Perform a Shodan scan on the target using the API key from environment.
    """
    load_dotenv()
    api_key = os.getenv("SHODAN_API_KEY")
    
    if not api_key:
        console.print("[red]❌ Shodan API key not found. Run 'bountybuddy setup' first.[/red]")
        return

    try:
        api = shodan.Shodan(api_key)
        console.print(f"[cyan]🔎 Querying Shodan for {target}...[/cyan]")
        
        # General host info
        try:
            # First try DNS resolution if it's a domain
            import socket
            ip_address = socket.gethostbyname(target)
            host_info = api.host(ip_address)
            
            console.print(f"[green]✓ Found host info for IP: {ip_address}[/green]")
            
            table = Table(title="Shodan Host Info")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("Organization", host_info.get('org', 'N/A'))
            table.add_row("OS", str(host_info.get('os', 'N/A')))
            table.add_row("Ports", str(host_info.get('ports', [])))
            table.add_row("Vulns", str(list(host_info.get('vulns', []))))
            
            console.print(table)
            
        except socket.gaierror:
             console.print(f"[yellow]⚠ Could not resolve {target} to IP. Trying search query...[/yellow]")
             # Fallback to search
             results = api.search(target)
             console.print(f"[green]✓ Found {results['total']} results for query '{target}'[/green]")
        except shodan.APIError as e:
            console.print(f"[red]⚠ Shodan API Error: {e}[/red]")

    except Exception as e:
        console.print(f"[red]❌ Error running Shodan scan: {e}[/red]")
