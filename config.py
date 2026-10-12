import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent

load_dotenv(REPO_ROOT / ".env")

GITHUB_REPO = "torvalds/linux"
GITHUB_REF = "v6.12"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise RuntimeError(f"GITHUB_TOKEN is not set; add it to {REPO_ROOT / '.env'}")