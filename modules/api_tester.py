#!/usr/bin/env python3
"""
API Security Tester Module
Tests for:
- Common endpoints
- Rate limiting
- Authentication bypass
- BOLA (IDOR)
- Mass assignment
- GraphQL introspection
- CORS misconfiguration
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse
import httpx


class APITester:
    """API Security Testing Module"""
    
    def __init__(self, auth_header: Optional[str] = None, timeout: int = 10):
        self.auth_header = auth_header
        self.timeout = timeout
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.findings: Dict[str, Any] = {}
        self.discovered_endpoints: Set[str] = set()
        self.common_paths = [
            "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
            "/swagger.json", "/swagger-ui.html", "/api-docs",
            "/.env", "/config.json", "/package.json",
            "/admin", "/dashboard", "/login", "/register",
            "/users", "/user", "/accounts", "/account",
            "/posts", "/articles", "/items", "/products",
            "/health", "/status", "/metrics", "/actuator"
        ]
        self.id_patterns = [
            r"/\d+",  # Numeric IDs
            r"/[0-9a-f]{8}-[0-9a-f]{4}",  # UUIDs
            r"/[0-9a-f]{24}",  # MongoDB ObjectIDs
        ]
    
    async def make_request(self, client: httpx.AsyncClient, url: str, 
                          method: str = "GET", headers: Optional[Dict] = None,
                          data: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Make HTTP request with auth if provided"""
        request_headers = headers or {}
        if self.auth_header:
            request_headers["Authorization"] = self.auth_header
        
        try:
            if method == "GET":
                return await client.get(url, headers=request_headers, timeout=self.timeout)
            elif method == "POST":
                return await client.post(url, headers=request_headers, json=data, timeout=self.timeout)
            elif method == "PUT":
                return await client.put(url, headers=request_headers, json=data, timeout=self.timeout)
            elif method == "DELETE":
                return await client.delete(url, headers=request_headers, timeout=self.timeout)
            elif method == "OPTIONS":
                return await client.options(url, headers=request_headers, timeout=self.timeout)
        except Exception as e:
            return None
        return None
    
    async def discover_endpoints(self, client: httpx.AsyncClient, 
                                 target: str) -> Set[str]:
        """Discover API endpoints"""
        endpoints = set()
        
        for path in self.common_paths:
            url = urljoin(target, path)
            try:
                response = await self.make_request(client, url)
                if response and response.status_code in [200, 401, 403, 301, 302]:
                    endpoints.add(url)
            except:
                pass
        
        # Check for OpenAPI/Swagger
        swagger_urls = [
            urljoin(target, "/swagger.json"),
            urljoin(target, "/swagger-ui.html"),
            urljoin(target, "/api-docs"),
            urljoin(target, "/openapi.json"),
            urljoin(target, "/v2/api-docs"),
            urljoin(target, "/v3/api-docs")
        ]
        
        for swagger_url in swagger_urls:
            try:
                response = await self.make_request(client, swagger_url)
                if response and response.status_code == 200:
                    endpoints.add(swagger_url)
                    self.vulnerabilities.append({
                        "severity": "LOW",
                        "type": "exposed_api_documentation",
                        "description": f"API documentation exposed at {swagger_url}",
                        "recommendation": "Restrict access to API documentation"
                    })
            except:
                pass
        
        return endpoints
    
    async def test_cors(self, client: httpx.AsyncClient, 
                        target: str) -> List[Dict]:
        """Test CORS configuration"""
        issues = []
        
        # Test origin reflection
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET"
        }
        
        try:
            response = await self.make_request(client, target, headers=headers)
            if response and hasattr(response, 'headers'):
                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")
                
                if acao == "https://evil.com" or acao == "*":
                    if acac and acac.lower() == "true":
                        issues.append({
                            "severity": "HIGH",
                            "type": "cors_misconfiguration",
                            "description": f"CORS allows arbitrary origin with credentials: {acao}",
                            "recommendation": "Validate and whitelist allowed origins"
                        })
                    else:
                        issues.append({
                            "severity": "MEDIUM",
                            "type": "cors_misconfiguration",
                            "description": f"CORS allows arbitrary origin: {acao}",
                            "recommendation": "Restrict allowed origins"
                        })
        except:
            pass
        
        return issues
    
    async def test_rate_limit(self, client: httpx.AsyncClient,
                              target: str) -> Optional[Dict]:
        """Test for rate limiting"""
        results = {
            "has_rate_limit": False,
            "rate_limit_headers": {},
            "requests_tested": 0
        }
        
        url = urljoin(target, "/")
        responses = []
        
        # Make 10 rapid requests
        for i in range(10):
            try:
                response = await self.make_request(client, url)
                if response:
                    responses.append(response.status_code)
                    results["requests_tested"] += 1
            except:
                break
        
        # Check for rate limit headers
        rate_limit_headers = [
            "x-rate-limit-limit",
            "x-rate-limit-remaining",
            "x-rate-limit-reset",
            "retry-after",
            "ratelimit-limit",
            "ratelimit-remaining"
        ]
        
        if response:
            for header in rate_limit_headers:
                if header in response.headers:
                    results["has_rate_limit"] = True
                    results["rate_limit_headers"][header] = response.headers[header]
        
        # Check if we got rate limited
        if 429 in responses or 503 in responses:
            results["has_rate_limit"] = True
        
        if not results["has_rate_limit"]:
            return {
                "severity": "LOW",
                "type": "missing_rate_limiting",
                "description": "No rate limiting detected",
                "recommendation": "Implement rate limiting to prevent abuse"
            }
        
        return None
    
    async def test_bola(self, client: httpx.AsyncClient,
                       target: str, wordlist: Optional[str] = None) -> List[Dict]:
        """Test for Broken Object Level Authorization (BOLA/IDOR)"""
        issues = []
        
        # Common ID-based endpoints
        bola_paths = [
            "/users/{id}", "/user/{id}", "/account/{id}",
            "/orders/{id}", "/order/{id}", "/posts/{id}",
            "/api/users/{id}", "/api/v1/users/{id}"
        ]
        
        test_ids = ["1", "2", "3", "100", "1000"]
        
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    test_ids.extend(line.strip() for line in f if line.strip())
            except:
                pass
        
        for path_template in bola_paths:
            for test_id in test_ids[:5]:  # Limit to prevent too many requests
                path = path_template.replace("{id}", test_id)
                url = urljoin(target, path)
                
                try:
                    response = await self.make_request(client, url)
                    if response and response.status_code == 200:
                        content_length = len(response.text)
                        if content_length > 100:  # Meaningful response
                            issues.append({
                                "severity": "HIGH",
                                "type": "bola_idor",
                                "description": f"Potential IDOR on {path} (ID: {test_id})",
                                "recommendation": "Verify authorization for resource access",
                                "evidence": f"Status: {response.status_code}, Length: {content_length}"
                            })
                            break
                except:
                    pass
        
        return issues
    
    async def test_graphql(self, client: httpx.AsyncClient,
                          target: str) -> List[Dict]:
        """Test GraphQL endpoints"""
        issues = []
        
        graphql_urls = [
            urljoin(target, "/graphql"),
            urljoin(target, "/api/graphql"),
            urljoin(target, "/v1/graphql")
        ]
        
        introspection_query = {
            "query": "\n            query IntrospectionQuery {\n                __schema {\n                    queryType { name }\n                    mutationType { name }\n                    subscriptionType { name }\n                    types {\n                        ...FullType\n                    }\n                }\n            }\n            fragment FullType on __Type {\n                name\n                fields {\n                    name\n                    type {\n                        name\n                    }\n                }\n            }\n            "
        }
        
        for url in graphql_urls:
            try:
                response = await self.make_request(client, url, method="POST", 
                                                    data=introspection_query)
                if response and response.status_code == 200:
                    data = response.json()
                    if data.get("data", {}).get("__schema"):
                        issues.append({
                            "severity": "MEDIUM",
                            "type": "graphql_introspection",
                            "description": f"GraphQL introspection enabled at {url}",
                            "recommendation": "Disable introspection in production"
                        })
            except:
                pass
        
        return issues
    
    async def test_mass_assignment(self, client: httpx.AsyncClient,
                                   target: str) -> List[Dict]:
        """Test for mass assignment vulnerabilities"""
        issues = []
        
        # Try to create/update with admin/internal fields
        sensitive_fields = [
            {"is_admin": True, "role": "admin"},
            {"admin": True, "is_superuser": True},
            {"role": "administrator", "privileges": "all"},
            {"id": 1, "user_id": 1}  # IDOR attempt
        ]
        
        test_urls = [
            urljoin(target, "/users"),
            urljoin(target, "/api/users"),
            urljoin(target, "/register"),
            urljoin(target, "/api/register")
        ]
        
        for url in test_urls:
            for data in sensitive_fields:
                try:
                    response = await self.make_request(client, url, method="POST", data=data)
                    if response and response.status_code in [200, 201]:
                        response_data = response.json() if "json" in response.headers.get("content-type", "") else {}
                        if any(k in str(response_data).lower() for k in ["admin", "role", "privilege"]):
                            issues.append({
                                "severity": "CRITICAL",
                                "type": "mass_assignment",
                                "description": f"Potential mass assignment at {url}",
                                "recommendation": "Whitelist allowed parameters, use DTOs"
                            })
                            break
                except:
                    pass
        
        return issues
    
    async def test(self, target: str, openapi: Optional[str] = None,
                  wordlist: Optional[str] = None) -> Dict[str, Any]:
        """Run full API security test"""
        self.vulnerabilities = []
        self.findings = {}
        
        # Ensure target has scheme
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
            # Discover endpoints
            self.discovered_endpoints = await self.discover_endpoints(client, target)
            
            # Run tests
            cors_issues = await self.test_cors(client, target)
            self.vulnerabilities.extend(cors_issues)
            
            rate_limit_issue = await self.test_rate_limit(client, target)
            if rate_limit_issue:
                self.vulnerabilities.append(rate_limit_issue)
            
            bola_issues = await self.test_bola(client, target, wordlist)
            self.vulnerabilities.extend(bola_issues)
            
            graphql_issues = await self.test_graphql(client, target)
            self.vulnerabilities.extend(graphql_issues)
            
            mass_assignment_issues = await self.test_mass_assignment(client, target)
            self.vulnerabilities.extend(mass_assignment_issues)
        
        self.findings = {
            "target": target,
            "discovered_endpoints": list(self.discovered_endpoints)[:20],
            "total_endpoints": len(self.discovered_endpoints)
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
                "low": len([v for v in self.vulnerabilities if v["severity"] == "LOW"])
            }
        }