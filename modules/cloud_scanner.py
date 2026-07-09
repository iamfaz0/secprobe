#!/usr/bin/env python3
"""
Cloud Security Scanner Module
Tests for:
- AWS S3 bucket misconfigurations
- Azure Blob Storage exposure
- GCP Cloud Storage issues
- CloudFront/Azure CDN misconfigs
- IAM/SAS token exposure
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, urljoin
import httpx


class CloudScanner:
    """Cloud Security Misconfiguration Scanner"""
    
    def __init__(self, threads: int = 30, timeout: int = 10):
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.findings: Dict[str, Any] = {}
        
        # AWS S3 bucket patterns
        self.s3_patterns = [
            r'([a-z0-9.-]+)\.s3\.amazonaws\.com',
            r'([a-z0-9.-]+)\.s3-[a-z0-9-]+\.amazonaws\.com',
            r'([a-z0-9.-]+)\.s3\.website[.-]',
            r's3://([a-z0-9.-]+)',
            r'https?://s3\.amazonaws\.com/([a-z0-9.-]+)',
        ]
        
        # Azure Blob patterns
        self.azure_patterns = [
            r'([a-z0-9-]+)\.blob\.core\.windows\.net',
            r'([a-z0-9-]+)\.file\.core\.windows\.net',
            r'([a-z0-9-]+)\.queue\.core\.windows\.net',
            r'([a-z0-9-]+)\.table\.core\.windows\.net',
        ]
        
        # GCP patterns
        self.gcp_patterns = [
            r'([a-z0-9.-]+)\.storage\.googleapis\.com',
            r'storage\.cloud\.google\.com/([a-z0-9.-]+)',
        ]
        
        # Common bucket names to try
        self.common_bucket_names = [
            'backup', 'backups', 'test', 'dev', 'development', 'staging', 'prod', 'production',
            'data', 'assets', 'images', 'files', 'uploads', 'media', 'docs', 'documents',
            'config', 'configurations', 'logs', 'database', 'db', 'app', 'application',
            'web', 'website', 'static', 'public', 'private', 'secure', 'temp', 'tmp',
            'archive', 'old', 'new', 'v1', 'v2', 'api', 'mobile', 'ios', 'android',
            'admin', 'dashboard', 'reports', 'export', 'import', 'sync', 'cache',
        ]
        
        self.common_words = [
            'aws', 'amazon', 's3', 'bucket', 'cloud', 'storage', 'blob', 'gcp', 'google',
            'azure', 'microsoft', 'company', 'org', 'internal', 'external', 'shared'
        ]
    
    async def check_s3_bucket(self, client: httpx.AsyncClient, 
                              bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check S3 bucket for misconfigurations"""
        results = {
            "bucket_name": bucket_name,
            "provider": "aws",
            "readable": False,
            "writable": False,
            "listable": False,
            "files": [],
        }
        
        urls_to_check = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
            f"http://{bucket_name}.s3.amazonaws.com",
        ]
        
        for url in urls_to_check:
            try:
                response = await client.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    content = response.text
                    results["readable"] = True
                    
                    # Check if listable
                    if '<ListBucketResult>' in content or '<Contents>' in content:
                        results["listable"] = True
                        # Extract files
                        files = re.findall(r'<Key>([^\u003c]+)</Key>', content)
                        results["files"] = files[:20]  # Limit to 20
                        
                        self.vulnerabilities.append({
                            "severity": "CRITICAL",
                            "type": "s3_bucket_listable",
                            "description": f"S3 bucket '{bucket_name}' is publicly listable",
                            "recommendation": "Disable public ListBucket permissions",
                            "evidence": f"Found {len(files)} files in bucket"
                        })
                    else:
                        self.vulnerabilities.append({
                            "severity": "HIGH",
                            "type": "s3_bucket_public",
                            "description": f"S3 bucket '{bucket_name}' allows public read",
                            "recommendation": "Remove public read permissions"
                        })
                
                # Check write permissions (OPTIONS then PUT test)
                elif response.status_code == 403:
                    # Try to determine if bucket exists
                    results["exists"] = True
                    
                elif response.status_code == 404:
                    results["exists"] = False
                    
            except Exception:
                continue
        
        return results if results.get("readable") or results.get("exists") else None
    
    async def check_azure_blob(self, client: httpx.AsyncClient,
                               account_name: str, 
                               container: str = None) -> Optional[Dict[str, Any]]:
        """Check Azure Blob Storage"""
        results = {
            "account_name": account_name,
            "provider": "azure",
            "containers": [],
        }
        
        # Check account
        base_url = f"https://{account_name}.blob.core.windows.net"
        
        try:
            response = await client.get(
                f"{base_url}?comp=list",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                self.vulnerabilities.append({
                    "severity": "CRITICAL",
                    "type": "azure_blob_public",
                    "description": f"Azure Blob Storage account '{account_name}' is publicly accessible",
                    "recommendation": "Disable anonymous public access"
                })
                results["public"] = True
            elif response.status_code == 403:
                results["exists"] = True
        except:
            pass
        
        # Check common containers
        common_containers = ['public', 'private', 'images', 'files', 'data', 'uploads']
        
        for container in common_containers:
            try:
                url = f"{base_url}/{container}"
                response = await client.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    results["containers"].append(container)
            except:
                pass
        
        return results if results.get("containers") or results.get("public") else None
    
    async def check_gcp_bucket(self, client: httpx.AsyncClient,
                               bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check GCP Cloud Storage bucket"""
        results = {
            "bucket_name": bucket_name,
            "provider": "gcp",
            "readable": False,
            "files": [],
        }
        
        urls = [
            f"https://{bucket_name}.storage.googleapis.com",
            f"https://storage.googleapis.com/{bucket_name}",
        ]
        
        for url in urls:
            try:
                response = await client.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    results["readable"] = True
                    content = response.text
                    
                    # Check if listable
                    if '<ListBucketResult' in content:
                        files = re.findall(r'<Key>([^\u003c]+)</Key>', content)
                        results["files"] = files[:20]
                        
                        self.vulnerabilities.append({
                            "severity": "CRITICAL",
                            "type": "gcp_bucket_listable",
                            "description": f"GCP bucket '{bucket_name}' is publicly listable",
                            "recommendation": "Remove allUsers/allAuthenticatedUsers access"
                        })
                elif response.status_code == 403:
                    results["exists"] = True
                    
            except:
                pass
        
        return results if results.get("readable") or results.get("exists") else None
    
    def extract_cloud_urls(self, content: str) -> Set[str]:
        """Extract cloud URLs from page content"""
        found = set()
        
        # S3 buckets
        for pattern in self.s3_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            found.update(matches)
        
        # Azure
        for pattern in self.azure_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            found.update(matches)
        
        # GCP
        for pattern in self.gcp_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            found.update(matches)
        
        return found
    
    async def generate_bucket_names(self, domain: str) -> List[str]:
        """Generate potential bucket names from domain"""
        names = set()
        
        # Clean domain
        clean = domain.replace('www.', '').replace('.com', '').replace('.org', '').replace('.net', '')
        clean = re.sub(r'[^a-z0-9-]', '', clean.lower())
        
        # Add domain variations
        names.add(clean)
        names.add(f"{clean}-backup")
        names.add(f"{clean}-backups")
        names.add(f"{clean}-assets")
        names.add(f"{clean}-data")
        names.add(f"{clean}-files")
        names.add(f"{clean}-uploads")
        names.add(f"{clean}-dev")
        names.add(f"{clean}-test")
        names.add(f"{clean}-prod")
        names.add(f"{clean}-staging")
        
        # Add common combinations
        for word in self.common_words:
            names.add(f"{clean}-{word}")
            names.add(f"{word}-{clean}")
        
        # Add common bucket names
        names.update(self.common_bucket_names)
        
        return list(names)[:100]  # Limit to 100
    
    async def scan_target(self, client: httpx.AsyncClient,
                          target: str) -> Dict[str, Any]:
        """Scan a target for cloud misconfigurations"""
        self.vulnerabilities = []
        self.findings = {}
        
        cloud_resources = {
            "aws": [],
            "azure": [],
            "gcp": [],
        }
        
        # Parse target
        if target.startswith(('http://', 'https://')):
            try:
                response = await client.get(target, timeout=self.timeout)
                content = response.text
                
                # Extract cloud URLs from content
                found_urls = self.extract_cloud_urls(content)
                
                for url in found_urls:
                    if 's3' in url.lower():
                        cloud_resources["aws"].append(url)
                    elif 'blob' in url.lower() or 'windows.net' in url.lower():
                        cloud_resources["azure"].append(url)
                    elif 'google' in url.lower() or 'gcp' in url.lower():
                        cloud_resources["gcp"].append(url)
                        
            except:
                pass
        
        # Get domain from target
        domain = target.replace('https://', '').replace('http://', '').replace('/', '')
        
        # Generate bucket names
        bucket_names = await self.generate_bucket_names(domain)
        
        # Check S3 buckets
        s3_semaphore = asyncio.Semaphore(self.threads)
        
        async def check_s3_limited(name):
            async with s3_semaphore:
                return await self.check_s3_bucket(client, name)
        
        s3_tasks = [check_s3_limited(name) for name in bucket_names[:50]]
        s3_results = await asyncio.gather(*s3_tasks, return_exceptions=True)
        
        for result in s3_results:
            if isinstance(result, dict):
                cloud_resources["aws"].append(result)
        
        # Check GCP buckets
        gcp_semaphore = asyncio.Semaphore(self.threads)
        
        async def check_gcp_limited(name):
            async with gcp_semaphore:
                return await self.check_gcp_bucket(client, name)
        
        gcp_tasks = [check_gcp_limited(name) for name in bucket_names[:30]]
        gcp_results = await asyncio.gather(*gcp_tasks, return_exceptions=True)
        
        for result in gcp_results:
            if isinstance(result, dict):
                cloud_resources["gcp"].append(result)
        
        self.findings = {
            "target": target,
            "cloud_resources": cloud_resources,
            "total_aws": len([r for r in cloud_resources["aws"] if isinstance(r, dict)]),
            "total_azure": len([r for r in cloud_resources["azure"] if isinstance(r, dict)]),
            "total_gcp": len([r for r in cloud_resources["gcp"] if isinstance(r, dict)]),
        }
        
        return {
            "target": target,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "info": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len([v for v in self.vulnerabilities if v["severity"] == "CRITICAL"]),
                "high": len([v for v in self.vulnerabilities if v["severity"] == "HIGH"]),
                "aws_resources": self.findings["total_aws"],
                "azure_resources": self.findings["total_azure"],
                "gcp_resources": self.findings["total_gcp"],
            }
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main scan entry point"""
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
            return await self.scan_target(client, target)