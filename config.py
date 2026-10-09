"""Central configuration. Everything is read from environment variables (.env locally)."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
# Change the model without touching code, e.g. GEMINI_MODEL=gemini-3.5-flash-lite
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

# Optional. Enables Google Safe Browsing link lookups (Lookup API v4, for non-commercial use).
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

PROMPT_FILE = BASE_DIR / os.getenv("PROMPT_FILE", "prompts/system_prompt.txt")
RECOVERY_PROMPT_FILE = BASE_DIR / "prompts" / "recovery_prompt.txt"

MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "4000"))
# Vercel rejects request bodies over 4.5 MB, so stay under that (the browser shrinks big screenshots first).
MAX_IMAGE_MB = float(os.getenv("MAX_IMAGE_MB", "4"))
MAX_IMAGE_BYTES = int(MAX_IMAGE_MB * 1024 * 1024)

# Protects a public demo link from burning through the Gemini quota.
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "10"))
DAILY_REQUEST_CAP = int(os.getenv("DAILY_REQUEST_CAP", "500"))

LANGUAGES = {"en": "English", "hi": "Hindi", "kn": "Kannada"}
MODES = {"simple", "detailed"}
