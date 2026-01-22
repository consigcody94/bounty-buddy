import subprocess
import shutil
import os
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

class ReconManager:
    def __init__(self, target: str, output_dir: str, console: Console):
        self.target = target
        self.output_dir = output_dir
        self.console = console
        os.makedirs(self.output_dir, exist_ok=True)

    def check_tool(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def run_subdomain_enum(self):
        self.console.print("[blue][+] Phase 1: Subdomain Enumeration[/blue]")
        
        # Check for subdomain-enum or fallbacks
        subdomains_file = os.path.join(self.output_dir, "subdomains.txt")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(description="Enumerating subdomains...", total=None)
            
            # Simple fallback logic for now, mirroring the bash script
            # In a real tool this would be more robust
            cmd = None
            if self.check_tool("subfinder"):
                 cmd = ["subfinder", "-d", self.target, "-silent", "-o", subdomains_file]
            
            if cmd:
                try:
                    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    count = 0
                    if os.path.exists(subdomains_file):
                        with open(subdomains_file) as f:
                            count = sum(1 for _ in f)
                    self.console.print(f"[green]✓ Found {count} subdomains (using subfinder)[/green]")
                except subprocess.CalledProcessError:
                    self.console.print("[red]❌ Error running subfinder[/red]")
            else:
                self.console.print("[yellow]⚠ No subdomain tools found (subfinder), skipping...[/yellow]")

    def run_httpx(self):
        self.console.print("[blue][+] Phase 2: Live Host Probing[/blue]")
        if not self.check_tool("httpx"):
             self.console.print("[yellow]⚠ httpx not found, skipping...[/yellow]")
             return

        subdomains_file = os.path.join(self.output_dir, "subdomains.txt")
        live_hosts_file = os.path.join(self.output_dir, "live-hosts.txt")
        
        if not os.path.exists(subdomains_file):
            self.console.print("[yellow]⚠ No subdomains file found to probe.[/yellow]")
            return

        cmd = ["httpx", "-l", subdomains_file, "-title", "-tech-detect", "-silent", "-o", live_hosts_file]
        
        with Progress(
             SpinnerColumn(),
             TextColumn("[progress.description]{task.description}"),
             console=self.console
        ) as progress:
            progress.add_task(description="Probing live hosts...", total=None)
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        count = 0
        if os.path.exists(live_hosts_file):
             with open(live_hosts_file) as f:
                 count = sum(1 for _ in f)
        self.console.print(f"[green]✓ Found {count} live hosts[/green]")

    def run_all(self):
        self.run_subdomain_enum()
        self.run_httpx()
        # Add other phases...
