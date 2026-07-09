"""
SecProbe Auto-Update Checker
Checks for updates from GitHub repository
"""

import urllib.request
import urllib.error
import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

# GitHub API URL for latest release
GITHUB_REPO = "iamfaz0/secprobe"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/commits/main"
GITHUB_RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/secprobe.py"
VERSION_FILE = Path.home() / ".secprobe" / "version_cache.json"

# Current version (embedded in secprobe.py)
CURRENT_VERSION = "2.0.0"


class UpdateChecker:
    """Checks for updates from GitHub"""
    
    def __init__(self):
        self.cache_file = VERSION_FILE
        self.cache_duration = timedelta(hours=24)  # Check once per day
        
    def _get_cache_dir(self):
        """Get or create cache directory"""
        cache_dir = Path.home() / ".secprobe"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir
    
    def _load_cache(self):
        """Load cached version info"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_cache(self, data):
        """Save version info to cache"""
        try:
            self._get_cache_dir()
            with open(self.cache_file, 'w') as f:
                json.dump(data, f)
        except Exception:
            pass
    
    def _should_check(self):
        """Check if we should check for updates"""
        cache = self._load_cache()
        if not cache:
            return True
        
        last_check = cache.get('last_check')
        if not last_check:
            return True
        
        try:
            last_check_time = datetime.fromisoformat(last_check)
            return datetime.now() - last_check_time > self.cache_duration
        except:
            return True
    
    def _get_remote_commit(self):
        """Get latest commit SHA from GitHub"""
        try:
            req = urllib.request.Request(
                GITHUB_API_URL,
                headers={
                    'User-Agent': 'SecProbe-UpdateChecker',
                    'Accept': 'application/vnd.github.v3+json'
                }
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return data.get('sha', '')
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Rate limited, skip check
                return None
            return None
        except Exception:
            return None
    
    def _get_local_commit(self):
        """Get current local commit SHA"""
        try:
            git_dir = Path(__file__).parent.parent / '.git'
            if git_dir.exists():
                head_file = git_dir / 'HEAD'
                if head_file.exists():
                    with open(head_file) as f:
                        ref = f.read().strip()
                        if ref.startswith('ref:'):
                            ref_file = git_dir / ref[5:]
                            if ref_file.exists():
                                with open(ref_file) as f:
                                    return f.read().strip()
            return None
        except Exception:
            return None
    
    def check_for_updates(self, force=False):
        """
        Check if updates are available
        Returns: (update_available, message)
        """
        if not force and not self._should_check():
            return False, None
        
        # Update last check time
        cache = self._load_cache()
        cache['last_check'] = datetime.now().isoformat()
        self._save_cache(cache)
        
        # Get remote commit
        remote_commit = self._get_remote_commit()
        if remote_commit is None:
            return False, None  # Couldn't check (offline/rate limited)
        
        # Get local commit
        local_commit = self._get_local_commit()
        if local_commit is None:
            # Not a git repo, check version in cache
            cached_commit = cache.get('remote_commit')
            if cached_commit and cached_commit != remote_commit:
                return True, self._format_update_message()
            cache['remote_commit'] = remote_commit
            self._save_cache(cache)
            return False, None
        
        # Compare commits
        if remote_commit != local_commit:
            return True, self._format_update_message()
        
        return False, None
    
    def _format_update_message(self):
        """Format update notification message"""
        return """[bold yellow]
⚡ UPDATE AVAILABLE ⚡[/bold yellow]

A new version of SecProbe is available on GitHub!

To update, run:
  [bold green]cd ~/secprobe && git pull origin main[/bold green]

Or reinstall:
  [bold green]cd ~ && rm -rf secprobe && git clone https://github.com/iamfaz0/secprobe.git && cd secprobe && ./install-kali.sh[/bold green]

[dim]Checking daily for updates. Set SECPROBE_NO_UPDATE_CHECK=1 to disable.[/dim]
"""
    
    def show_update_banner(self):
        """Check and display update notification"""
        # Skip if disabled
        if os.environ.get('SECPROBE_NO_UPDATE_CHECK') == '1':
            return
        
        try:
            update_available, message = self.check_for_updates()
            if update_available and message:
                console.print(message)
                console.print()
        except Exception:
            # Silently fail - don't block tool usage
            pass


# Global instance
update_checker = UpdateChecker()


def check_updates(force=False):
    """Public function to check for updates"""
    return update_checker.check_for_updates(force)


def show_update_if_available():
    """Show update banner if available"""
    update_checker.show_update_banner()
