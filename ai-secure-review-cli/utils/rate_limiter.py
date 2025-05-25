# utils/rate_limiter.py
import asyncio
import time
from collections import deque
from typing import Optional

class RateLimiter:
    """Rate limiter for API calls"""
    
    def __init__(self, max_calls: int, time_window: int = 60):
        """
        Initialize rate limiter
        
        Args:
            max_calls: Maximum number of calls allowed
            time_window: Time window in seconds (default: 60)
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = deque()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make an API call"""
        async with self._lock:
            now = time.time()
            
            # Remove old calls outside the time window
            while self.calls and self.calls[0] <= now - self.time_window:
                self.calls.popleft()
            
            # If we're at the limit, wait
            if len(self.calls) >= self.max_calls:
                # Calculate how long to wait
                oldest_call = self.calls[0]
                wait_time = self.time_window - (now - oldest_call)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    # Remove the old call after waiting
                    self.calls.popleft()
            
            # Record this call
            self.calls.append(now)
    
    def get_remaining_calls(self) -> int:
        """Get number of remaining calls in current window"""
        now = time.time()
        
        # Remove old calls
        while self.calls and self.calls[0] <= now - self.time_window:
            self.calls.popleft()
        
        return max(0, self.max_calls - len(self.calls))
    
    def get_reset_time(self) -> Optional[float]:
        """Get time when rate limit resets"""
        if not self.calls:
            return None
        
        return self.calls[0] + self.time_window



