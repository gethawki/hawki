# File: hawki/core/deep/budget.py
"""
Dual budget manager for attempts and token usage.
"""

from typing import Optional


class BudgetManager:
    def __init__(self, max_attempts: Optional[int] = None, max_tokens: Optional[int] = None):
        self.max_attempts = max_attempts
        self.max_tokens = max_tokens
        self.attempts_used = 0
        self.tokens_used = 0

    def can_continue(self) -> bool:
        if self.max_attempts is not None and self.attempts_used >= self.max_attempts:
            return False
        if self.max_tokens is not None and self.tokens_used >= self.max_tokens:
            return False
        return True

    def consume(self, attempts: int = 1, tokens: int = 0) -> None:
        self.attempts_used += attempts
        self.tokens_used += tokens

    def remaining_attempts(self) -> Optional[int]:
        if self.max_attempts is None:
            return None
        return max(0, self.max_attempts - self.attempts_used)

    def remaining_tokens(self) -> Optional[int]:
        if self.max_tokens is None:
            return None
        return max(0, self.max_tokens - self.tokens_used)
    
    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token estimate: 1 token ≈ 4 characters."""
        return len(text) // 4

# EOF