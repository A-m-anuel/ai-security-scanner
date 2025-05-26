import re
from typing import Dict, Any

class TokenCounter:
    """Utility for counting and managing API tokens"""
    
    def __init__(self):
        self.total_tokens_used = 0
        self.tokens_by_model = {}
    
    def estimate_tokens(self, text: str, model: str = "gpt-4") -> int:
        """
        Estimate token count for text
        This is a rough estimation - for accurate counts use tiktoken
        """
        if model.startswith("gpt"):
            # Rough estimation: ~4 characters per token for English
            return len(text) // 4
        elif "claude" in model:
            # Claude has similar tokenization to GPT
            return len(text) // 4
        else:
            # Default estimation
            return len(text.split())
    
    def add_usage(self, model: str, prompt_tokens: int, completion_tokens: int):
        """Record token usage"""
        total = prompt_tokens + completion_tokens
        self.total_tokens_used += total
        
        if model not in self.tokens_by_model:
            self.tokens_by_model[model] = {
                'prompt_tokens': 0,
                'completion_tokens': 0,
                'total_tokens': 0
            }
        
        self.tokens_by_model[model]['prompt_tokens'] += prompt_tokens
        self.tokens_by_model[model]['completion_tokens'] += completion_tokens
        self.tokens_by_model[model]['total_tokens'] += total
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get summary of token usage"""
        return {
            'total_tokens': self.total_tokens_used,
            'by_model': self.tokens_by_model
        }
    
    def estimate_cost(self, model: str = "gpt-4") -> float:
        """Estimate cost based on token usage (rough estimates)"""
        if model not in self.tokens_by_model:
            return 0.0
        
        # Rough pricing estimates (as of 2024)
        pricing = {
            'gpt-4': {'prompt': 0.03/1000, 'completion': 0.06/1000},
            'gpt-3.5-turbo': {'prompt': 0.001/1000, 'completion': 0.002/1000},
            'claude-3-sonnet': {'prompt': 0.015/1000, 'completion': 0.075/1000}
        }
        
        if model not in pricing:
            return 0.0
        
        model_usage = self.tokens_by_model[model]
        cost = (
            model_usage['prompt_tokens'] * pricing[model]['prompt'] +
            model_usage['completion_tokens'] * pricing[model]['completion']
        )
        
        return cost