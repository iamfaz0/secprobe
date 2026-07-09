"""
Vulnerability Database Module
SQLite-based storage for scan results with search capabilities
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table

console = Console()

DB_PATH = Path.home() / ".secprobe" / "scans.db"


class VulnDatabase:
    """SQLite database for storing scan results"""
    
    def __init__(self):
        self.db_path = DB_PATH
        self._ensure_db()
    
    def _ensure_db(self):
        """Create database and tables if not exists"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                results TEXT NOT NULL,
                total_vulns INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0
            )
        ''')
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                title TEXT NOT NULL,
                vuln_type TEXT,
                severity TEXT,
                description TEXT,
                module TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, target: str, scan_type: str, results: Dict[str, Any]) -> int:
        """Save scan results to database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        # Count vulnerabilities by severity
        vulns = results.get('vulnerabilities', [])
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulns:
            sev = vuln.get('severity', 'LOW').upper()
            if sev in counts:
                counts[sev] += 1
        
        # Insert scan
        cursor.execute('''
            INSERT INTO scans (target, scan_type, timestamp, results, total_vulns,
                             critical_count, high_count, medium_count, low_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (target, scan_type, timestamp, json.dumps(results), len(vulns),
              counts['CRITICAL'], counts['HIGH'], counts['MEDIUM'], counts['LOW']))
        
        scan_id = cursor.lastrowid
        
        # Insert vulnerabilities
        for vuln in vulns:
            cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, title, vuln_type, severity,
                                            description, module)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, vuln.get('title', ''), vuln.get('type', ''),
                  vuln.get('severity', ''), vuln.get('description', ''),
                  vuln.get('module', '')))
        
        conn.commit()
        conn.close()
        
        return scan_id
    
    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent scans"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, target, scan_type, timestamp, total_vulns,
                   critical_count, high_count, medium_count, low_count
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'target': row[1],
                'scan_type': row[2],
                'timestamp': row[3],
                'total_vulns': row[4],
                'critical': row[5],
                'high': row[6],
                'medium': row[7],
                'low': row[8]
            })
        
        conn.close()
        return scans
    
    def search_vulns(self, query: str = None, severity: str = None,
                     target: str = None, vuln_type: str = None) -> List[Dict[str, Any]]:
        """Search vulnerabilities"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        sql = '''
            SELECT v.id, v.title, v.vuln_type, v.severity, v.description,
                   v.module, s.target, s.timestamp
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE 1=1
        '''
        params = []
        
        if query:
            sql += " AND (v.title LIKE ? OR v.description LIKE ?)"
            params.extend([f'%{query}%', f'%{query}%'])
        
        if severity:
            sql += " AND v.severity = ?"
            params.append(severity.upper())
        
        if target:
            sql += " AND s.target LIKE ?"
            params.append(f'%{target}%')
        
        if vuln_type:
            sql += " AND v.vuln_type = ?"
            params.append(vuln_type)
        
        sql += " ORDER BY s.timestamp DESC"
        
        cursor.execute(sql, params)
        
        vulns = []
        for row in cursor.fetchall():
            vulns.append({
                'id': row[0],
                'title': row[1],
                'type': row[2],
                'severity': row[3],
                'description': row[4],
                'module': row[5],
                'target': row[6],
                'timestamp': row[7]
            })
        
        conn.close()
        return vulns
    
    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get scan by ID"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans WHERE id = ?
        ''', (scan_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'target': row[1],
                'scan_type': row[2],
                'timestamp': row[3],
                'results': json.loads(row[4]),
                'total_vulns': row[5],
                'critical': row[6],
                'high': row[7],
                'medium': row[8],
                'low': row[9]
            }
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        total_vulns = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT severity, COUNT(*) FROM vulnerabilities
            GROUP BY severity
        ''')
        severity_counts = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT target, COUNT(*) FROM scans
            GROUP BY target
            ORDER BY COUNT(*) DESC
            LIMIT 10
        ''')
        top_targets = [{'target': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'top_targets': top_targets
        }
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete scan by ID"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False


# Global instance
vuln_db = VulnDatabase()


def save_scan(target: str, scan_type: str, results: Dict[str, Any]) -> int:
    """Public function to save scan"""
    return vuln_db.save_scan(target, scan_type, results)


def search_vulns(**kwargs) -> List[Dict[str, Any]]:
    """Public function to search vulnerabilities"""
    return vuln_db.search_vulns(**kwargs)


def list_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """Public function to list scans"""
    return vuln_db.list_scans(limit)
