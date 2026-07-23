# --------------------
# File: hawki/core/monitoring/watchers/repo_commit_watcher.py
# --------------------
"""
Watcher that polls a Git repository for new commits.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import git
from git.exc import InvalidGitRepositoryError

from ..watcher_base import Watcher

logger = logging.getLogger(__name__)

class RepoCommitWatcher(Watcher):
    """Monitors a local Git repository for new commits."""

    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.repo_path = Path(config.get("repo_path", ".")).resolve()
        self.branch = config.get("branch", "main")
        self._last_commit = None
        self._valid_repo = None  # cache validity check

    def _is_git_repo(self) -> bool:
        """Check if the path is a valid Git repository."""
        if self._valid_repo is not None:
            return self._valid_repo
        try:
            _ = git.Repo(self.repo_path)
            self._valid_repo = True
        except (InvalidGitRepositoryError, Exception):
            self._valid_repo = False
            logger.warning(f"Path is not a Git repository: {self.repo_path}")
        return self._valid_repo

    def check(self) -> Optional[Dict[str, Any]]:
        """Check for new commits since last check."""
        if not self._is_git_repo():
            return None

        try:
            repo = git.Repo(self.repo_path)
            # Ensure we have the latest remote info
            origin = repo.remotes.origin if repo.remotes else None
            if origin:
                origin.fetch()

            # Get latest commit hash on the branch
            latest_commit = repo.commit(self.branch).hexsha
            previous = self.state.get("last_commit")

            if previous is None:
                # First run, store current hash but don't alert
                self.state["last_commit"] = latest_commit
                return None

            if latest_commit != previous:
                # New commit detected
                commit = repo.commit(latest_commit)
                event = {
                    "type": "new_commit",
                    "repo": str(self.repo_path),
                    "branch": self.branch,
                    "commit_hash": latest_commit,
                    "message": commit.message.strip(),
                    "author": str(commit.author),
                    "timestamp": commit.committed_datetime.isoformat(),
                    "new_message": f"New commit in {self.repo_path.name}: {commit.message[:50]}",
                }
                self.state["last_commit"] = latest_commit
                return event
            return None
        except Exception as e:
            logger.error(f"RepoCommitWatcher error: {e}")
            return None

# EOF: hawki/core/monitoring/watchers/repo_commit_watcher.py