"""
Report Templates Module
Generate reports in multiple formats: HTML, PDF, Markdown
"""

import json
import base64
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
from rich.console import Console

console = Console()


class ReportTemplates:
    """Generate reports in various formats"""
    
    HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecProbe Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 16px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        .header .meta {{
            opacity: 0.8;
            font-size: 1rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .stat-card.critical {{
            border-left: 4px solid #ef4444;
        }}
        .stat-card.high {{
            border-left: 4px solid #f97316;
        }}
        .stat-card.medium {{
            border-left: 4px solid #eab308;
        }}
        .stat-card.low {{
            border-left: 4px solid #22c55e;
        }}
        .stat-card.info {{
            border-left: 4px solid #3b82f6;
        }}
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            opacity: 0.7;
            font-size: 0.9rem;
        }}
        .section {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5rem;
        }}
        .vulnerability {{
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid #ef4444;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
        }}
        .vulnerability.high {{
            background: rgba(249, 115, 22, 0.1);
            border-left-color: #f97316;
        }}
        .vulnerability.medium {{
            background: rgba(234, 179, 8, 0.1);
            border-left-color: #eab308;
        }}
        .vulnerability.low {{
            background: rgba(34, 197, 94, 0.1);
            border-left-color: #22c55e;
        }}
        .vuln-title {{
            font-weight: bold;
            margin-bottom: 8px;
        }}
        .vuln-meta {{
            font-size: 0.85rem;
            opacity: 0.7;
            margin-bottom: 10px;
        }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-critical {{
            background: #ef4444;
            color: #fff;
        }}
        .severity-high {{
            background: #f97316;
            color: #fff;
        }}
        .severity-medium {{
            background: #eab308;
            color: #000;
        }}
        .severity-low {{
            background: #22c55e;
            color: #fff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        th {{
            background: rgba(102, 126, 234, 0.2);
            font-weight: 600;
        }}
        tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            opacity: 0.6;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SecProbe Security Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {target} | <strong>Generated:</strong> {timestamp}</p>
                <p><strong>Tool:</strong> SecProbe v2.0.0 | <strong>Scan Type:</strong> {scan_type}</p>
            </div>
        </div>
        
        <div class="stats-grid">
            {stats_html}
        </div>
        
        {vulnerabilities_html}
        
        {findings_html}
        
        <div class="footer">
            <p>Generated by SecProbe v2.0.0 - Advanced Penetration Testing Toolkit</p>
            <p>⚠️ This report contains security-sensitive information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
'''
    
    def __init__(self):
        pass
    
    def generate_html(self, data: Dict[str, Any], output_path: str):
        """Generate HTML report"""
        target = data.get('target', 'Unknown')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        scan_type = data.get('scan_type', 'Full Scan')
        
        # Build stats HTML
        stats = data.get('stats', {})
        stats_html = self._build_stats_html(stats)
        
        # Build vulnerabilities HTML
        vulns = data.get('vulnerabilities', [])
        vulnerabilities_html = self._build_vulnerabilities_html(vulns)
        
        # Build findings HTML
        findings = data.get('findings', {})
        findings_html = self._build_findings_html(findings)
        
        # Generate full HTML
        html = self.HTML_TEMPLATE.format(
            target=target,
            timestamp=timestamp,
            scan_type=scan_type,
            stats_html=stats_html,
            vulnerabilities_html=vulnerabilities_html,
            findings_html=findings_html
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def generate_markdown(self, data: Dict[str, Any], output_path: str):
        """Generate Markdown report"""
        target = data.get('target', 'Unknown')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        md = f"""# 🔒 SecProbe Security Report

## Executive Summary

- **Target:** {target}
- **Scan Date:** {timestamp}
- **Tool:** SecProbe v2.0.0

## Statistics

"""
        
        stats = data.get('stats', {})
        for key, value in stats.items():
            md += f"- **{key.replace('_', ' ').title()}:** {value}\n"
        
        md += "\n## Vulnerabilities\n\n"
        
        vulns = data.get('vulnerabilities', [])
        for vuln in vulns:
            severity = vuln.get('severity', 'UNKNOWN')
            md += f"### [{severity}] {vuln.get('title', 'Unknown')}\n\n"
            md += f"- **Type:** {vuln.get('type', 'N/A')}\n"
            md += f"- **Description:** {vuln.get('description', 'N/A')}\n"
            md += f"- **Recommendation:** {vuln.get('recommendation', 'N/A')}\n\n"
        
        md += """\n---

*Generated by SecProbe - Advanced Penetration Testing Toolkit*
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)
        
        return output_path
    
    def _build_stats_html(self, stats: Dict[str, Any]) -> str:
        """Build statistics cards HTML"""
        html = ''
        
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info'
        }
        
        for key, value in stats.items():
            sev_class = severity_map.get(key.lower(), 'info')
            label = key.replace('_', ' ').title()
            html += f'''
            <div class="stat-card {sev_class}">
                <div class="stat-value">{value}</div>
                <div class="stat-label">{label}</div>
            </div>
            '''
        
        return html
    
    def _build_vulnerabilities_html(self, vulns: List[Dict]) -> str:
        """Build vulnerabilities section HTML"""
        if not vulns:
            return '<div class="section"><h2>Vulnerabilities</h2><p>No vulnerabilities found. ✓</p></div>'
        
        html = '<div class="section"><h2>Vulnerabilities</h2>'
        
        for vuln in vulns:
            severity = vuln.get('severity', 'LOW').lower()
            html += f'''
            <div class="vulnerability {severity}">
                <div class="vuln-title">{vuln.get('title', 'Unknown')}</div>
                <div class="vuln-meta">
                    <span class="severity severity-{severity}">{severity.upper()}</span> |
                    Module: {vuln.get('module', 'N/A')}
                </div>
                <p>{vuln.get('description', 'No description')}</p>
                <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'N/A')}</p>
            </div>
            '''
        
        html += '</div>'
        return html
    
    def _build_findings_html(self, findings: Dict[str, Any]) -> str:
        """Build findings section HTML"""
        html = '<div class="section"><h2>Technical Findings</h2>'
        
        # Open ports table
        if 'open_ports' in findings and findings['open_ports']:
            html += '<h3>Open Ports</h3>'
            html += '<table><thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead><tbody>'
            for port in findings['open_ports']:
                html += f"<tr><td>{port.get('port', 'N/A')}</td><td>{port.get('state', 'N/A')}</td><td>{port.get('service', 'N/A')}</td></tr>"
            html += '</tbody></table>'
        
        # Technologies
        if 'technologies' in findings and findings['technologies']:
            html += '<h3>Detected Technologies</h3><ul>'
            for tech in findings['technologies']:
                html += f"<li>{tech}</li>"
            html += '</ul>'
        
        html += '</div>'
        return html


# Global instance
report_templates = ReportTemplates()


def generate_report(data: Dict[str, Any], output_path: str, format_type: str = 'html'):
    """Public function to generate report"""
    if format_type.lower() == 'html':
        return report_templates.generate_html(data, output_path)
    elif format_type.lower() == 'md' or format_type.lower() == 'markdown':
        return report_templates.generate_markdown(data, output_path)
    else:
        # Default to HTML
        return report_templates.generate_html(data, output_path)
