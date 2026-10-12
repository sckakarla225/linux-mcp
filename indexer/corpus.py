"""Lists the in-scope files at the pinned ref and fetches them for the index build."""

import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import scope
from config import GITHUB_REF
from github import GitHubClient, GitHubError

FETCH_WORKERS = 24

# Folders whose full listing is kept so that paths written in docs can be checked for
# existence, even when the files themselves are out of scope.
KNOWN_PATH_ROOTS = ["Documentation", "include", "net", "kernel", "lib", "drivers/net", "drivers/infiniband"]


@dataclass
class Corpus:
    docs: dict[str, str] = field(default_factory=dict)  # path under Documentation/ -> text
    code: dict[str, str] = field(default_factory=dict)  # repo path -> text
    extra: dict[str, str] = field(default_factory=dict)  # MAINTAINERS etc.
    blob_sha: dict[str, str] = field(default_factory=dict)  # repo path -> git blob sha
    known_paths: set[str] = field(default_factory=set)  # every blob under KNOWN_PATH_ROOTS
    known_roots: list[str] = field(default_factory=list)
    commit_sha: str = ""

    def path_is_listed(self, path: str) -> bool | None:
        """True/False when the path's folder was listed; None when it was not."""
        if not any(path == root or path.startswith(root + "/") for root in self.known_roots):
            return None
        return path in self.known_paths


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _subtree_sha(client: GitHubClient, root_entries: dict[str, dict], path: str) -> str:
    parts = path.split("/")
    entry = root_entries[parts[0]]
    for part in parts[1:]:
        entry = next(e for e in client.tree(entry["sha"]) if e["path"] == part)
    return entry["sha"]


def load(client: GitHubClient) -> Corpus:
    corpus = Corpus()
    root = client.tree(GITHUB_REF)
    root_entries = {entry["path"]: entry for entry in root}

    for folder in KNOWN_PATH_ROOTS:
        try:
            entries = client.tree(_subtree_sha(client, root_entries, folder), recursive=True)
        except GitHubError as exc:
            _log(f"  listing {folder}: {exc}; paths under it will not be checked")
            continue
        corpus.known_roots.append(folder)
        for entry in entries:
            if entry["type"] == "blob":
                path = f"{folder}/{entry['path']}"
                corpus.known_paths.add(path)
                corpus.blob_sha[path] = entry["sha"]
    for entry in root:
        if entry["type"] == "blob":
            corpus.blob_sha[entry["path"]] = entry["sha"]

    missing_roots = [r for r in ("Documentation", "include", "net", "kernel", "lib", "drivers/net")
                     if r not in corpus.known_roots]
    if missing_roots:
        raise GitHubError(f"could not list {missing_roots}; the index cannot be built")

    doc_paths = sorted(
        path[len("Documentation/"):]
        for path in corpus.known_paths
        if path.startswith("Documentation/") and scope.doc_in_scope(path[len("Documentation/"):])
    )
    code_paths = sorted(path for path in corpus.known_paths if scope.code_in_scope(path))
    _log(f"  in scope: {len(doc_paths)} docs, {len(code_paths)} code files")

    jobs = (
        [("doc", p, f"Documentation/{p}") for p in doc_paths]
        + [("code", p, p) for p in code_paths]
        + [("extra", p, p) for p in scope.EXTRA_BUILD_INPUTS]
    )
    with ThreadPoolExecutor(FETCH_WORKERS) as pool:
        texts = list(pool.map(lambda job: client.fetch_text(job[2]), jobs))
    for (kind, key, _), text in zip(jobs, texts):
        getattr(corpus, {"doc": "docs", "code": "code", "extra": "extra"}[kind])[key] = text
    return corpus
