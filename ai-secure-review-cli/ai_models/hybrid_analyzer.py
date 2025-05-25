# ai_models/hybrid_analyzer.py - Simplified version
from .huggingface_analyzer import HuggingFaceAnalyzer

class HybridAnalyzer(HuggingFaceAnalyzer):
    """Simplified hybrid analyzer that extends the existing analyzer"""
    
    def __init__(self, config, pattern_only=False):
        super().__init__(config, pattern_only=pattern_only)
        self.hybrid_mode = not pattern_only
        
        if self.hybrid_mode:
            print("[HYBRID] AI + Pattern mode enabled")
        else:
            print("[HYBRID] Pattern-only mode")