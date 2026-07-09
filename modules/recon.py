#!/usr/bin/env python3
"""
Reconnaissance Module
- Port scanning
- Subdomain enumeration
- Technology detection
- Directory discovery
"""

import asyncio
import socket
import ssl
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse
import httpx


class ReconModule:
    """Network and Web Reconnaissance"""
    
    def __init__(self, threads: int = 50, timeout: int = 5):
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[Dict] = []
        self.findings: Dict = {}
        self.common_subdomains = [
            "www", "mail", "ftp", "localhost", "admin", "blog", "shop",
            "forum", "news", "test", "dev", "api", "staging", "demo",
            "app", "mobile", "secure", "vpn", "dns", "mx", "ns1", "ns2",
            "cdn", "static", "img", "media", "videos", "download", "support",
            "help", "docs", "wiki", "status", "monitor", "grafana", "prometheus",
            "kibana", "elasticsearch", "jenkins", "gitlab", "github", "bitbucket",
            "jira", "confluence", "redmine", "docker", "kubernetes", "kube"
        ]
        self.common_dirs = [
            "/admin", "/login", "/wp-admin", "/administrator",
            "/config", "/backup", "/.git", "/.env",
            "/api", "/swagger", "/api-docs",
            "/uploads", "/files", "/images", "/assets",
            "/phpmyadmin", "/mysql", "/db"
        ]
        self.tech_signatures = {
            "WordPress": ["/wp-content", "/wp-includes", "wp-json"],
            "Drupal": ["/sites/default", "/modules"],
            "Joomla": ["/administrator", "/components"],
            "Apache": ["Apache", "apache"],
            "Nginx": ["nginx", "NGINX"],
            "IIS": ["IIS", "Microsoft-IIS"],
            "Cloudflare": ["cloudflare", "CF-RAY"],
            "AWS": ["aws", "amazonaws", "s3"],
            "Azure": ["azure", "windows-azure"],
            "PHP": [".php", "X-Powered-By: PHP"],
            "ASP.NET": ["ASP.NET", "__VIEWSTATE"],
            "Python": ["Python", "Django", "Flask"],
            "Ruby": ["Ruby", "Rails"],
            "Node.js": ["Express", "Node.js"],
            "Java": ["Tomcat", "Jetty", "Spring"],
        }
    
    async def scan_port(self, host: str, port: int) -> Optional[Dict]:
        """Scan a single port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Try to grab banner
            banner = ""
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner = banner.decode('utf-8', errors='ignore')[:200]
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            service = self.identify_service(port, banner)
            
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner[:100] if banner else ""
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception:
            return None
    
    def identify_service(self, port: int, banner: str) -> str:
        """Identify service from port and banner"""
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 3306: "mysql", 5432: "postgresql",
            6379: "redis", 27017: "mongodb", 8080: "http-proxy",
            8443: "https-alt", 3000: "http-dev", 5000: "http-dev"
        }
        
        service = common_services.get(port, "unknown")
        
        # Try to identify from banner
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            service = "ssh"
        elif "http" in banner_lower:
            service = "http"
        elif "smtp" in banner_lower:
            service = "smtp"
        elif "ftp" in banner_lower:
            service = "ftp"
        
        return service
    
    async def scan_ports(self, host: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports concurrently"""
        semaphore = asyncio.Semaphore(self.threads)
        
        async def scan_with_limit(port):
            async with semaphore:
                return await self.scan_port(host, port)
        
        tasks = [scan_with_limit(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for result in results:
            if isinstance(result, dict) and result:
                open_ports.append(result)
        
        return open_ports
    
    async def enumerate_subdomains(self, domain: str) -> List[Dict]:
        """Enumerate subdomains via DNS"""
        subdomains = []
        semaphore = asyncio.Semaphore(20)
        
        async def check_subdomain(sub):
            async with semaphore:
                subdomain = f"{sub}.{domain}"
                try:
                    addrinfo = await asyncio.wait_for(
                        asyncio.get_event_loop().getaddrinfo(subdomain, None),
                        timeout=3
                    )
                    if addrinfo:
                        ips = list(set([info[4][0] for info in addrinfo]))
                        return {"subdomain": subdomain, "ips": ips}
                except:
                    pass
                return None
        
        tasks = [check_subdomain(sub) for sub in self.common_subdomains]
        results = await asyncio.gather(*tasks)
        
        return [r for r in results if r]
    
    async def detect_tech(self, client: httpx.AsyncClient, 
                          url: str) -> Dict[str, List[str]]:
        """Detect technologies used by target"""
        detected = {}
        
        try:
            response = await client.get(url, timeout=self.timeout)
            headers = dict(response.headers)
            content = response.text.lower()
            
            for tech, signatures in self.tech_signatures.items():
                found = False
                for sig in signatures:
                    sig_lower = sig.lower()
                    # Check headers
                    for header, value in headers.items():
                        if sig_lower in header.lower() or sig_lower in value.lower():
                            found = True
                            break
                    # Check content
                    if sig_lower in content:
                        found = True
                        break
                    # Check URL
                    if sig_lower in url.lower():
                        found = True
                        break
                
                if found:
                    detected[tech] = signatures[:2]
        except:
            pass
        
        return detected
    
    async def check_ssl(self, host: str, port: int = 443) -> Optional[Dict]:
        """Check SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    issues = []
                    
                    # Check SSL/TLS version
                    if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        issues.append(f"Insecure protocol version: {version}")
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        from datetime import datetime
                        expiry = cert['notAfter']
                        # Simple check - would need proper parsing
                        issues.append(f"Cert expires: {expiry}")
                    
                    return {
                        "protocol": version,
                        "cipher": cipher[0] if cipher else "unknown",
                        "issues": issues
                    }
        except:
            return None
    
    async def discover_directories(self, client: httpx.AsyncClient,
                                   base_url: str) -> List[Dict]:
        """Discover common directories"""
        found = []
        semaphore = asyncio.Semaphore(10)
        
        async def check_dir(dir_path):
            async with semaphore:
                url = f"{base_url.rstrip('/')}{dir_path}"
                try:
                    response = await client.get(url, timeout=self.timeout)
                    if response.status_code in [200, 301, 302, 401, 403]:
                        return {
                            "path": dir_path,
                            "url": url,
                            "status": response.status_code,
                            "size": len(response.content)
                        }
                except:
                    pass
                return None
        
        tasks = [check_dir(d) for d in self.common_dirs]
        results = await asyncio.gather(*tasks)
        
        return [r for r in results if r]
    
    async def scan(self, target: str, 
                   ports: Optional[str] = None) -> Dict[str, Any]:
        """Run full reconnaissance scan"""
        self.vulnerabilities = []
        self.findings = {}
        
        # Parse target
        parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        host = parsed.hostname or target
        
        # Parse ports
        if ports:
            port_list = []
            for p in ports.split(','):
                if '-' in p:
                    start, end = map(int, p.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(p))
        else:
            port_list = [80, 443, 8080, 8443, 3000, 5000, 8000]
        
        # Port scanning
        open_ports = await self.scan_ports(host, port_list)
        
        # Technology detection
        tech = {}
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # Try HTTPS first
            if any(p["port"] == 443 for p in open_ports):
                try:
                    tech = await self.detect_tech(client, f"https://{host}")
                except:
                    pass
            
            # Try HTTP
            if not tech:
                try:
                    tech = await self.detect_tech(client, f"http://{host}")
                except:
                    pass
            
            # Directory discovery
            discovered_dirs = []
            if any(p["port"] == 80 for p in open_ports):
                discovered_dirs = await self.discover_directories(client, f"http://{host}")
            if any(p["port"] == 443 for p in open_ports):
                discovered_dirs = await self.discover_directories(client, f"https://{host}")
        
        # Subdomain enumeration
        subdomains = await self.enumerate_subdomains(host)
        
        # SSL check for HTTPS
        ssl_info = None
        if any(p["port"] == 443 for p in open_ports):
            ssl_info = await self.check_ssl(host)
            if ssl_info and ssl_info.get("issues"):
                for issue in ssl_info["issues"]:
                    if "Insecure" in issue:
                        self.vulnerabilities.append({
                            "severity": "HIGH",
                            "type": "weak_ssl",
                            "description": issue,
                            "recommendation": "Upgrade to TLS 1.2 or higher"
                        })
        
        # Check for exposed sensitive paths
        for dir_info in discovered_dirs:
            if dir_info["path"] in ["/.git", "/.env", "/config", "/backup"]:
                self.vulnerabilities.append({
                    "severity": "CRITICAL",
                    "type": "sensitive_exposure",
                    "description": f"Potentially sensitive path exposed: {dir_info['path']}",
                    "recommendation": "Restrict access or remove sensitive files",
                    "url": dir_info["url"]
                })
        
        self.findings = {
            "host": host,
            "ip": socket.gethostbyname(host) if host else None,
            "open_ports": open_ports,
            "technologies": tech,
            "subdomains": subdomains[:10],
            "directories": discovered_dirs,
            "ssl_info": ssl_info
        }
        
        return {
            "target": target,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "info": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "open_ports": len(open_ports),
                "subdomains_found": len(subdomains),
                "directories_found": len(discovered_dirs),
                "technologies": len(tech)
            }
        }