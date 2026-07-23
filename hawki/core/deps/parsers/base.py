# File: hawki/core/deps/parsers/base.py
"""
Base utilities for lockfile parsers.
"""
import re


def clean_version(version: str) -> str:
    """Remove leading ^, ~, =, v and return a clean version string."""
    cleaned = re.sub(r'^[\^~=v]', '', version)
    return cleaned
# EOF
