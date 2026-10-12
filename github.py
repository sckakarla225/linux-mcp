"""GitHub access for torvalds/linux at the pinned ref.

Used by the index build (tree listings, bulk file fetches) and by the server (live fetches).
Fetched files are cached in memory for the life of the process. The server never writes to
disk; the index build can opt into a disk cache so that rebuilds do not refetch every file.
"""

import hashlib
import logging
import threading
import time
from pathlib import Path

import httpx2

from config import GITHUB_REF, GITHUB_REPO, GITHUB_TOKEN

API_ROOT = f"https://api.github.com/repos/{GITHUB_REPO}"
RAW_ROOT = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_REF}"
BLOB_ROOT = f"https://github.com/{GITHUB_REPO}/blob/{GITHUB_REF}"

# One log line per request would flood the stderr of a stdio server.
logging.getLogger("httpx2").setLevel(logging.WARNING)

RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 5


class GitHubError(RuntimeError):
    pass


def permalink(path: str, start_line: int | None = None, end_line: int | None = None) -> str:
    url = f"{BLOB_ROOT}/{path}"
    if start_line is None:
        return url
    if end_line is None or end_line == start_line:
        return f"{url}#L{start_line}"
    return f"{url}#L{start_line}-L{end_line}"


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class GitHubClient:
    def __init__(self, cache_dir: Path | None = None, max_connections: int = 16):
        self._client = httpx2.Client(
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "User-Agent": "linux-mcp",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=httpx2.Timeout(30.0),
            limits=httpx2.Limits(max_connections=max_connections),
            follow_redirects=True,
        )
        self._cache: dict[str, bytes] = {}
        self._lock = threading.Lock()
        self._cache_dir = cache_dir
        self.requests = 0
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def _get(self, url: str, **kwargs) -> httpx2.Response:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self._client.get(url, **kwargs)
            except httpx2.TransportError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise GitHubError(f"GitHub request failed for {url}: {exc}") from exc
                time.sleep(attempt)
                continue
            with self._lock:
                self.requests += 1
            rate_limited = response.status_code == 403 and (
                response.headers.get("x-ratelimit-remaining") == "0"
                or "retry-after" in response.headers
            )
            if rate_limited:
                reset = response.headers.get("x-ratelimit-reset", "unknown")
                raise GitHubError(
                    f"GitHub rate limit reached (resets at epoch {reset}); wait and retry"
                )
            if response.status_code in RETRY_STATUSES and attempt < MAX_ATTEMPTS:
                time.sleep(attempt)
                continue
            return response
        raise GitHubError(f"GitHub request failed for {url}")

    def tree(self, sha_or_ref: str, recursive: bool = False) -> list[dict]:
        """List a git tree. Entries have path, type ("blob" or "tree"), sha and size."""
        params = {"recursive": "1"} if recursive else None
        response = self._get(f"{API_ROOT}/git/trees/{sha_or_ref}", params=params)
        if response.status_code != 200:
            raise GitHubError(f"tree {sha_or_ref}: HTTP {response.status_code}")
        body = response.json()
        if body.get("truncated"):
            raise GitHubError(f"tree {sha_or_ref} was truncated by GitHub; list it per subfolder")
        return body["tree"]

    def fetch_bytes(self, path: str) -> bytes:
        """Fetch one file at the pinned ref."""
        with self._lock:
            cached = self._cache.get(path)
        if cached is not None:
            return cached
        # Keyed by a hash of the path: the tree has paths differing only in case (xt_DSCP.c and
        # xt_dscp.c), which collide on case-insensitive filesystems such as macOS's default.
        disk_path = (
            self._cache_dir / hashlib.sha1(path.encode()).hexdigest()
            if self._cache_dir is not None else None
        )
        if disk_path is not None and disk_path.is_file():
            data = disk_path.read_bytes()
        else:
            response = self._get(f"{RAW_ROOT}/{path}")
            if response.status_code == 404:
                raise GitHubError(f"{path} does not exist at {GITHUB_REF}")
            if response.status_code != 200:
                raise GitHubError(f"{path}: HTTP {response.status_code}")
            data = response.content
            if disk_path is not None:
                disk_path.parent.mkdir(parents=True, exist_ok=True)
                disk_path.write_bytes(data)
        with self._lock:
            self._cache[path] = data
        return data

    def fetch_text(self, path: str) -> str:
        return self.fetch_bytes(path).decode("utf-8", errors="replace")

    def fetch_lines(self, path: str) -> list[str]:
        return self.fetch_text(path).split("\n")

    def rate_limit(self) -> dict:
        return self._get("https://api.github.com/rate_limit").json()["resources"]["core"]

    def close(self) -> None:
        self._client.close()
