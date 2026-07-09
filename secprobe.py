#!/usr/bin/env python3
"""
SecProbe - Advanced Penetration Testing Toolkit
A powerful, Termux-friendly security testing tool
Author: iamfaz0
"""

import asyncio
import argparse
import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

# Import modules
from modules.jwt_auditor import JWTAuditor
from modules.api_tester import APITester
from modules.recon import ReconModule
from modules.cloud_scanner import CloudScanner
from modules.web_fuzzer import WebFuzzer
from modules.report_generator import ReportGenerator

console = Console()

BANNER = """
[bold blue]
  ..######..##.....##.####..........###....########...######..########
  .##....##.##.....##..##..........##.##...##.....##.##....##.##......
  .##.......##.....##..##.........##...##..##.....##.##.......##......
  ..######..##.....##..##........##.....##.########..##.......######..
  .......##.##.....##..##........#########.##...##...##.......##......
  .##....##.##.....##..##........##.....##.##....##..##....##.##......
  ..######...#######..####.......##.....##.##.....##..######..########
[/bold blue]
[bold red]
         .;okKXNNNWNXK0xo:.
      .:OXWWWWWWWWWWWWWWWWKd'           ████████████████████████████████████
    .cKWWWWWWWWWWWWWWWWWWWWWW0c         ████████  ██  ██ ██  ██  ████████
   ;0WWWWWWWWWWWWWWWWWWWWWWWWWXo        ████  ████ ████ █████ ████ ████  ████
  ;KWWWWWWWWWWWWWWWWWWWWWWWWWWWWk.      ████    ██ ██ ████ ████ ██ ████    ██
 .kWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW0'     ████  ████ ██  ██ ██  ██ ████  ████
 lXWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWO.    ████████  ██  ██ ██  ██  ████████
.OX0OO0KXWWWWWWWWWWWWWWWWWWWWWWWWWWx.   
'Ol.   .:d0NWWWWWWWWWWWWWWWWWWWWWWWW0'  [cyan]Kali Linux Compatible Security Toolkit[/cyan]
 .         .:ONWWWWWWWWWWWWWWWWWWWWWNd. [cyan]v2.0.0 | Made by iamfaz0[/cyan]
             .kWWWWWWWWWWWWWWWWWWWWWWK;
              cKWWWWWWWWWWWWWWWWWWWWWO.
              .kWWWWWWWWWWWWWWWWWWWWWX:
               lNWWWWWWWWWWWWWWWWWWWWWd.
               .kWWWWWWWWWWWWWWWWWWWWK,
                cXWWWWWWWWWWWWWWWWWWWO.
                .xNWWWWWWWWWWWWWWWWWX:
                 'kWWWWWWWWWWWWWWWWWd.
                  'xXWWWWWWWWWWWWWWk'
                    'cxOKXNNNXK0xc.
[/bold red]
"""

class SecProbe:
    """Main application class"""
    
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.report_generator = ReportGenerator()
    
    def show_banner(self):
        console.print(BANNER)
    
    async def run_jwt_audit(self, target: str, wordlist: Optional[str] = None, 
                           exploit: bool = False) -> Dict:
        """Run JWT security audit"""
        auditor = JWTAuditor()
        with console.status("[bold yellow]Running JWT Security Audit...") as status:
            results = await auditor.audit(target, wordlist, exploit)
        return results
    
    async def run_api_test(self, target: str, openapi: Optional[str] = None,
                          wordlist: Optional[str] = None, auth: Optional[str] = None) -> Dict:
        """Run API security tests"""
        tester = APITester(auth_header=auth)
        with console.status("[bold yellow]Running API Security Tests...") as status:
            results = await tester.test(target, openapi, wordlist)
        return results
    
    async def run_recon(self, target: str, ports: Optional[str] = None,
                       threads: int = 50) -> Dict:
        """Run reconnaissance"""
        recon = ReconModule(threads=threads)
        with console.status("[bold yellow]Running Reconnaissance...") as status:
            results = await recon.scan(target, ports)
        return results
    
    async def run_cloud_scan(self, target: str) -> Dict:
        """Run cloud security scan"""
        scanner = CloudScanner()
        with console.status("[bold yellow]Running Cloud Security Scan...") as status:
            results = await scanner.scan(target)
        return results
    
    async def run_web_fuzz(self, target: str) -> Dict:
        """Run web fuzzer"""
        fuzzer = WebFuzzer()
        with console.status("[bold yellow]Running Web Fuzzer...") as status:
            results = await fuzzer.scan(target)
        return results
    
    def display_results(self, module: str, results: Dict):
        """Display results in a nice table"""
        console.print(f"\n[bold green]╔{'═' * 68}╗[/bold green]")
        console.print(f"[bold green]║[/bold green] [bold white]{module.upper():^66}[/bold white] [bold green]║[/bold green]")
        console.print(f"[bold green]╚{'═' * 68}╝[/bold green]\n")
        
        if "vulnerabilities" in results and results["vulnerabilities"]:
            vuln_table = Table(title="[bold red]Vulnerabilities Found[/bold red]")
            vuln_table.add_column("Severity", style="bold")
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Description", style="white")
            
            for vuln in results["vulnerabilities"]:
                severity = vuln.get("severity", "INFO")
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", 
                        "LOW": "blue", "INFO": "green"}.get(severity, "white")
                vuln_table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    vuln.get("type", "Unknown"),
                    vuln.get("description", "No description")
                )
            console.print(vuln_table)
        
        if "findings" in results and results["findings"]:
            findings_table = Table(title="[bold yellow]Security Findings[/bold yellow]")
            findings_table.add_column("Finding", style="cyan")
            findings_table.add_column("Value", style="white")
            
            for key, value in results["findings"].items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                findings_table.add_row(str(key), str(value)[:50])
            console.print(findings_table)
        
        if "info" in results:
            info_table = Table(title="[bold blue]Scan Information[/bold blue]")
            info_table.add_column("Property", style="cyan")
            info_table.add_column("Value", style="white")
            
            for key, value in results["info"].items():
                info_table.add_row(str(key), str(value))
            console.print(info_table)
        
        console.print()


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="SecProbe - Advanced Penetration Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # JWT Audit
  secprobe jwt --target eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.wordlist.txt
  
  # API Security Test
  secprobe api --target https://api.example.com --auth "Bearer token123"
  
  # Reconnaissance
  secprobe recon --target example.com --ports 80,443,8080
  
  # Cloud Scan
  secprobe cloud --target example.com
  
  # Web Fuzzer
  secprobe fuzz --target https://example.com
  
  # Full Scan
  secprobe full --target example.com -o report.json
        """
    )
    
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 2.0.0")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # JWT Command
    jwt_parser = subparsers.add_parser("jwt", help="JWT Security Auditor")
    jwt_parser.add_argument("-t", "--target", required=True, help="JWT token to analyze")
    jwt_parser.add_argument("-w", "--wordlist", help="Wordlist for brute force")
    jwt_parser.add_argument("--exploit", action="store_true", help="Attempt exploitation")
    jwt_parser.add_argument("--alg-none", action="store_true", help="Test alg:none attack")
    jwt_parser.add_argument("-o", "--output", help="Output file for report (JSON)")
    jwt_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # API Command
    api_parser = subparsers.add_parser("api", help="API Security Tester")
    api_parser.add_argument("-t", "--target", required=True, help="Target API URL")
    api_parser.add_argument("--openapi", help="OpenAPI/Swagger spec URL or file")
    api_parser.add_argument("-w", "--wordlist", help="Wordlist for fuzzing")
    api_parser.add_argument("--auth", help="Authorization header value")
    api_parser.add_argument("--graphql", action="store_true", help="Test GraphQL endpoint")
    api_parser.add_argument("-o", "--output", help="Output file for report (JSON)")
    api_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # Recon Command
    recon_parser = subparsers.add_parser("recon", help="Reconnaissance Module")
    recon_parser.add_argument("-t", "--target", required=True, help="Target domain/IP")
    recon_parser.add_argument("-p", "--ports", default="80,443", help="Ports to scan")
    recon_parser.add_argument("--threads", type=int, default=50, help="Thread count")
    recon_parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    recon_parser.add_argument("--tech-detect", action="store_true", help="Detect technologies")
    recon_parser.add_argument("-o", "--output", help="Output file for report (JSON)")
    recon_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # Cloud Command
    cloud_parser = subparsers.add_parser("cloud", help="Cloud Security Scanner")
    cloud_parser.add_argument("-t", "--target", required=True, help="Target domain/URL")
    cloud_parser.add_argument("--threads", type=int, default=30, help="Thread count")
    cloud_parser.add_argument("-o", "--output", help="Output file for report (JSON)")
    cloud_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # Fuzz Command
    fuzz_parser = subparsers.add_parser("fuzz", help="Web Fuzzer")
    fuzz_parser.add_argument("-t", "--target", required=True, help="Target URL")
    fuzz_parser.add_argument("--threads", type=int, default=30, help="Thread count")
    fuzz_parser.add_argument("-o", "--output", help="Output file for report (JSON)")
    fuzz_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    # Full Command
    full_parser = subparsers.add_parser("full", help="Full Security Assessment")
    full_parser.add_argument("-t", "--target", required=True, help="Target URL/Domain")
    full_parser.add_argument("-p", "--ports", default="80,443,8080,8443", help="Ports to scan")
    full_parser.add_argument("--threads", type=int, default=50, help="Thread count")
    full_parser.add_argument("--wordlist", help="Wordlist for brute force/fuzzing")
    full_parser.add_argument("-o", "--output", help="Output file for report (JSON)")
    full_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    return parser


async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Check for quiet flag
    quiet_mode = args.quiet
    
    # Initialize app
    app = SecProbe()
    
    if not quiet_mode:
        app.show_banner()
    
    results = {}
    
    try:
        if args.command == "jwt":
            results["jwt"] = await app.run_jwt_audit(
                args.target, 
                args.wordlist, 
                args.exploit
            )
            if not quiet_mode:
                app.display_results("JWT Security Audit", results["jwt"])
        
        elif args.command == "api":
            results["api"] = await app.run_api_test(
                args.target,
                args.openapi,
                args.wordlist,
                args.auth
            )
            if not quiet_mode:
                app.display_results("API Security Test", results["api"])
        
        elif args.command == "recon":
            results["recon"] = await app.run_recon(
                args.target,
                args.ports,
                args.threads
            )
            if not quiet_mode:
                app.display_results("Reconnaissance", results["recon"])
        
        elif args.command == "cloud":
            results["cloud"] = await app.run_cloud_scan(
                args.target
            )
            if not quiet_mode:
                app.display_results("Cloud Security Scan", results["cloud"])
        
        elif args.command == "fuzz":
            results["fuzz"] = await app.run_web_fuzz(
                args.target
            )
            if not quiet_mode:
                app.display_results("Web Fuzzer", results["fuzz"])
        
        elif args.command == "full":
            if not quiet_mode:
                console.print("[bold yellow]Starting Full Security Assessment...[/bold yellow]\n")
            
            # Run all modules
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                console=console
            ) as progress:
                
                task = progress.add_task("Running reconnaissance...", total=None)
                results["recon"] = await app.run_recon(
                    args.target, args.ports, args.threads
                )
                progress.update(task, description="Reconnaissance complete!")
                
                task = progress.add_task("Testing API endpoints...", total=None)
                results["api"] = await app.run_api_test(
                    args.target, wordlist=args.wordlist
                )
                progress.update(task, description="API testing complete!")
            
            # Display summary
            if not quiet_mode:
                console.print("\n[bold green]=== FULL ASSESSMENT COMPLETE ===[/bold green]\n")
                for module, data in results.items():
                    vuln_count = len(data.get("vulnerabilities", []))
                    console.print(f"[bold]{module.upper()}:[/bold] {vuln_count} vulnerabilities found")
        
        # Save report if requested
        if args.output:
            report_gen = ReportGenerator()
            report_gen.save_json(results, args.output)
            if not quiet_mode:
                console.print(f"\n[bold green]Report saved to: {args.output}[/bold green]")
    
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())