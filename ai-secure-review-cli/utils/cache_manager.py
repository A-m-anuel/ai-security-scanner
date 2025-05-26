import json
import hashlib
import os
from typing import Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

class CacheManager:
    """Simple file-based cache for analysis results"""
    
    def __init__(self, cache_dir: str = ".cache", ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
    
    def _get_cache_key(self, data: Any) -> str:
        """Generate cache key from data"""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()
    
    def _get_cache_path(self, key: str) -> Path:
        """Get path for cache file"""
        return self.cache_dir / f"{key}.json"
    
    def get(self, key_data: Any) -> Optional[Any]:
        """Get cached data"""
        key = self._get_cache_key(key_data)
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            return None
        
        try:
            # Check if cache is expired
            file_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
            if datetime.now() - file_time > self.ttl:
                cache_path.unlink()  # Delete expired cache
                return None
            
            with open(cache_path, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            print(f"Error reading cache: {e}")
            return None
    
    def set(self, key_data: Any, value: Any):
        """Set cached data"""
        key = self._get_cache_key(key_data)
        cache_path = self._get_cache_path(key)
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(value, f, indent=2, default=str)
        except Exception as e:
            print(f"Error writing cache: {e}")
    
    def clear(self):
        """Clear all cached data"""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except Exception as e:
                print(f"Error deleting cache file {cache_file}: {e}")
    
    def clear_expired(self):
        """Clear only expired cache entries"""
        now = datetime.now()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                file_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                if now - file_time > self.ttl:
                    cache_file.unlink()
            except Exception as e:
                print(f"Error checking cache file {cache_file}: {e}")
