"""
CVE Database Integration Module
Matches findings against known CVEs using NVD API
"""

import urllib.request
import urllib.error
import json
import asyncio
import ssl
from typing import List, Dict, Any, Optional
from rich.console import Console

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEChecker:
    """Checks vulnerabilities against CVE database"""
    
    def __init__(self):
        self.cache: Dict[str, Any] = {}
        
    def _api_request(self, keyword: str) -> Optional[Dict]:
        """Query NVD API for CVEs matching keyword"""
        try:
            url = f"{NVD_API_BASE}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=5"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'SecProbe-CVEChecker/2.0.0',
                    'Accept': 'application/json'
                }
            )
            
            with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
                return json.loads(response.read().decode())
        except Exception:
            return None
    
    def check_vulnerability(self, vuln_type: str, tech: str = "") -> List[Dict[str, Any]]:
        """
        Check vulnerability against CVE database
        Returns list of matching CVEs
        """
        search_term = f"{vuln_type} {tech}".strip()
        
        if search_term in self.cache:
            return self.cache[search_term]
        
        data = self._api_request(search_term)
        
        if not data or 'vulnerabilities' not in data:
            return []
        
        cves = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'N/A')
            
            # Get description
            descriptions = cve.get('descriptions', [])
            desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), 'No description')
            
            # Get CVSS score
            metrics = cve.get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0] or {}
            score = cvss_data.get('cvssData', {}).get('baseScore', 'N/A')
            severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'N/A')
            
            cves.append({
                'id': cve_id,
                'description': desc[:200] + '...' if len(desc) > 200 else desc,
                'score': score,
                'severity': severity,
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        
        self.cache[search_term] = cves
        return cves
    
    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add CVE information to findings"""
        enriched = []
        
        with console.status("[bold yellow]Checking CVE database...") as status:
            for finding in findings:
                vuln_type = finding.get('type', '')
                module = finding.get('module', '')
                
                # Look up CVEs
                cves = self.check_vulnerability(vuln_type, module)
                
                finding['cves'] = cves
                finding['cve_count'] = len(cves)
                
                enriched.append(finding)
        
        return enriched
    
    def get_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get CVE summary for findings"""
        total_cves = sum(f.get('cve_count', 0) for f in findings)
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'N/A': 0}
        
        for finding in findings:
            for cve in finding.get('cves', []):
                sev = cve.get('severity', 'N/A').upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        return {
            'total_cves_found': total_cves,
            'severity_breakdown': severity_counts,
            'findings_with_cves': len([f for f in findings if f.get('cves')])
        }


# Global instance
cve_checker = CVEChecker()


def check_cves(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Public function to check CVEs for findings"""
    return cve_checker.enrich_findings(findings)
