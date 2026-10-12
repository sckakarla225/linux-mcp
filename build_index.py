"""Build index.db from torvalds/linux at the pinned ref.

    .venv/bin/python build_index.py [--cache-dir DIR] [--output PATH]

Lists the in-scope folders through the GitHub API, fetches every in-scope file from
raw.githubusercontent.com, and writes the index. --cache-dir keeps the fetched files on disk
so that a rebuild (for example after changing index code) does not fetch them again.
"""

import argparse
import json
from pathlib import Path

import db
from indexer.build import build


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", type=Path, default=db.INDEX_PATH, help="where to write the index")
    parser.add_argument("--cache-dir", type=Path, default=None, help="keep fetched files here between builds")
    parser.add_argument("--stats", action="store_true", help="print index statistics as JSON when done")
    args = parser.parse_args()
    temporary = args.output.with_suffix(".db.building")
    stats = build(temporary, args.cache_dir)
    temporary.replace(args.output)
    if args.stats:
        print(json.dumps(stats, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
