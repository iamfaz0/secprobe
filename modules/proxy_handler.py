#!/usr/bin/env python3
"""
Proxy Handler Module
Supports HTTP, SOCKS4, SOCKS5 proxies and Tor
"""

import os
from typing import Optional, Dict, Any
import httpx


class ProxyHandler:
    """Handle proxy configuration for HTTP requests"""
    
    def __init__(self, proxy_url: Optional[str] = None):
        self.proxy_url = proxy_url
        self.proxies = self._parse_proxy(proxy_url)
    
    def _parse_proxy(self, proxy_url: Optional[str]) -> Dict[str, str]:
        """Parse proxy URL into httpx format"""
        if not proxy_url:
            return {}
        
        # Handle Tor shortcut
        if proxy_url.lower() == 'tor':
            return {
                'http://': 'socks5://127.0.0.1:9050',
                'https://': 'socks5://127.0.0.1:9050'
            }
        
        # Handle direct format
        return {
            'http://': proxy_url,
            'https://': proxy_url
        }
    
    def get_client(self, **kwargs) -> httpx.AsyncClient:
        """Get httpx client with proxy configured"""
        if self.proxies:
            kwargs['proxies'] = self.proxies
        return httpx.AsyncClient(**kwargs)
    
    @staticmethod
    def install_tor_deps():
        """Show instructions for installing SOCKS support"""
        return """
To use SOCKS proxies (including Tor), install:

  pip install httpx[socks]

Or:

  pip install httpcore[socks]
"""


# Global instance
proxy_handler = ProxyHandler()


def set_proxy(proxy_url: Optional[str]):
    """Set global proxy"""
    global proxy_handler
    proxy_handler = ProxyHandler(proxy_url)


def get_proxy_client(**kwargs) -> httpx.AsyncClient:
    """Get client with current proxy settings"""
    return proxy_handler.get_client(**kwargs)
