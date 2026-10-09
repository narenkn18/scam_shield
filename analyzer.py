"""Gemini calls, prompt assembly and output validation.

The model's answer is never trusted blindly: it is parsed, type-checked and passed
through guardrails (verdict/score consistency, injection handling) before reaching the UI.
"""
import functools
import json
import logging
import re
import time

import config
import urlcheck

log = logging.getLogger("scamshield")

VERDICTS = ("SAFE", "SUSPICIOUS", "SCAM")
CONFIDENCE = ("LOW", "MEDIUM", "HIGH")
TAGS = (
    "URGENCY", "THREAT", "IMPERSONATION", "OTP_REQUEST", "SENSITIVE_DATA",
    "SUSPICIOUS_LINK", "PAYMENT_REQUEST", "TOO_GOOD_TO_BE_TRUE", "SECRECY",
    "AI_INJECTION", "OTHER",
)
# Score bands per verdict so the number on screen always agrees with the badge.
SCORE_BANDS = {"SAFE": (0, 30), "SUSPICIOUS": (31, 69), "SCAM": (70, 100)}
WHEN = ("now", "today", "week")

_client = None


class AnalyzerError(Exception):
    """An error with a message that is safe to show to the user."""

    def __init__(self, message, status=502):
        super().__init__(message)
        self.message = message
        self.status = status


@functools.lru_cache(maxsize=8)
def load_prompt(path):
    """Read a prompt file once per process (failures are not cached)."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        log.error("Prompt file missing: %s", path.name)
        raise AnalyzerError("The server is missing its prompt files. Check the deployment bundle.", 500) from e


def _get_client():
    global _client
    if _client is None:
        if not config.GEMINI_API_KEY:
            raise AnalyzerError(
                "The server has no Gemini API key. Add GEMINI_API_KEY to your .env file or hosting settings.", 500
            )
        from google import genai  # imported lazily so tests run without network setup

        _client = genai.Client(api_key=config.GEMINI_API_KEY)
    return _client


# ----------------------------------------------------------------- prompt assembly
_DELIMITER_RE = re.compile(r"</?\s*message_to_analyze\s*>", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize(text):
    """Strip control characters and stop the sender from closing our data delimiter early."""
    text = _CONTROL_RE.sub("", text or "")
    return _DELIMITER_RE.sub("[removed]", text).strip()


def build_contents(text, language_code, mode, image_bytes=None, image_mime=None, url_facts=""):
    """Return the `contents` list for generate_content. The message is wrapped as data."""
    language = config.LANGUAGES.get(language_code, "English")
    header = f"OUTPUT_LANGUAGE: {language}\nEXPLANATION_MODE: {mode.upper()}\n"
    if url_facts:
        # Computed by our own code (hosts only, validated), so it sits outside the untrusted data tags.
        header += "URL_FACTS (computed by the system, not written by the sender):\n" + url_facts + "\n"
    clean = sanitize(text)
    if image_bytes:
        header += "The message to analyze is in the attached screenshot. Read it carefully.\n"
        if not clean:
            clean = "(see attached screenshot)"
    body = f"<message_to_analyze>\n{clean}\n</message_to_analyze>"
    parts = []
    if image_bytes:
        from google.genai import types

        parts.append(types.Part.from_bytes(data=image_bytes, mime_type=image_mime))
    parts.append(header + body)
    return parts


# ----------------------------------------------------------------- model call
def raw_generate(system_prompt, contents, json_mode=True):
    """One Gemini call. Returns the text. Raises AnalyzerError with a friendly message."""
    from google.genai import errors, types

    client = _get_client()
    cfg = types.GenerateContentConfig(
        system_instruction=system_prompt,
        temperature=0.2,
        max_output_tokens=4096,
        response_mime_type="application/json" if json_mode else None,
    )
    max_retries = 3
    last_err = None
    for attempt in range(max_retries):
        try:
            resp = client.models.generate_content(model=config.MODEL, contents=contents, config=cfg)
            text = getattr(resp, "text", None)
            if not text:
                raise AnalyzerError(
                    "The AI could not analyze this content (it may have been blocked by safety filters). "
                    "Treat it with caution and do not interact with it.", 502,
                )
            return text
        except errors.APIError as e:
            code = getattr(e, "code", None)
            last_err = e
            log.warning("Gemini API error code=%s attempt=%d", code, attempt + 1)
            if code in (429, 503) and attempt < max_retries - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            if code == 429:
                raise AnalyzerError("The AI service is busy right now. Please try again in a minute.", 503) from e
            if code in (401, 403) or "API key" in str(e):
                raise AnalyzerError("The server's Gemini API key was rejected. Check GEMINI_API_KEY.", 500) from e
            raise AnalyzerError("The AI service had a problem. Please try again.", 502) from e
        except AnalyzerError:
            raise
        except Exception as e:
            log.exception("Unexpected error calling Gemini")
            raise AnalyzerError("Could not reach the AI service. Check your connection and try again.", 502) from e

    raise AnalyzerError("The AI service is busy right now. Please try again in a minute.", 503) from last_err


def parse_json(text):
    """Parse model output as JSON, tolerating code fences or stray text around the object."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.IGNORECASE)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        start, end = t.find("{"), t.rfind("}")
        if start != -1 and end > start:
            return json.loads(t[start : end + 1])
        raise


def _generate_json(system_prompt, contents):
    """Call the model and parse JSON; retry once if the output is not valid JSON."""
    last = None
    for attempt in (1, 2):
        text = raw_generate(system_prompt, contents, json_mode=True)
        try:
            data = parse_json(text)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError as e:
            last = e
            log.warning("Invalid JSON from model (attempt %s)", attempt)
    raise AnalyzerError("The AI returned an unreadable answer. Please try again.", 502) from last


# ----------------------------------------------------------------- validation
def _s(value, limit):
    return str(value).strip()[:limit] if value is not None else ""


def normalize_analysis(d):
    verdict = _s(d.get("verdict"), 20).upper()
    if verdict not in VERDICTS:
        verdict = "SUSPICIOUS"
    try:
        score = int(float(d.get("risk_score", 50)))
    except (TypeError, ValueError):
        score = 50
    conf = _s(d.get("confidence"), 10).upper()
    if conf not in CONFIDENCE:
        conf = "LOW"

    injection = d.get("injection_attempt_detected") in (True, "true", "True")

    flags = []
    for f in (d.get("red_flags") or [])[:12]:
        if not isinstance(f, dict):
            continue
        phrase = _s(f.get("phrase"), 200)
        tag = _s(f.get("tag"), 30).upper()
        flags.append({
            "phrase": phrase,
            "tag": tag if tag in TAGS else "OTHER",
            "why": _s(f.get("why"), 300),
        })
        if flags[-1]["tag"] == "AI_INJECTION":
            injection = True

    # Guardrail: a message that tries to give orders to the AI is never SAFE.
    if injection and verdict == "SAFE":
        verdict = "SUSPICIOUS"
        score = max(score, 60)

    lo, hi = SCORE_BANDS[verdict]
    score = max(lo, min(hi, score))

    steps = [_s(x, 300) for x in (d.get("next_steps") or [])[:8] if x]
    return {
        "verdict": verdict,
        "risk_score": score,
        "confidence": conf,
        "scam_type": _s(d.get("scam_type"), 80) or "None",
        "injection_attempt_detected": injection,
        "extracted_text": _s(d.get("extracted_text"), config.MAX_TEXT_CHARS),
        "red_flags": flags,
        "explanation": _s(d.get("explanation"), 1500),
        "next_steps": steps,
        "share_message": _s(d.get("share_message"), 600),
    }


def normalize_recovery(d):
    steps = []
    for s in (d.get("steps") or [])[:12]:
        if isinstance(s, dict) and s.get("action"):
            when = _s(s.get("when"), 10).lower()
            steps.append({"when": when if when in WHEN else "today", "action": _s(s["action"], 400)})
    if not steps:
        raise AnalyzerError("The AI returned an empty plan.", 502)
    steps.sort(key=lambda s: WHEN.index(s["when"]))  # stable: keeps the model's order within a group
    return {
        "urgency_banner": _s(d.get("urgency_banner"), 200),
        "steps": steps,
        "complaint_summary": _s(d.get("complaint_summary"), 2000),
        "source": "ai",
    }


def apply_url_guardrails(result, url_checks):
    """A link that Google Safe Browsing flags makes the message a SCAM, whatever the model said."""
    result["url_checks"] = url_checks
    flagged = [u for u in url_checks if u.get("safe_browsing") == "flagged"]
    if flagged and result["verdict"] != "SCAM":
        result["verdict"] = "SCAM"
        result["risk_score"] = max(result["risk_score"], SCORE_BANDS["SCAM"][0])
        result["confidence"] = "HIGH"
    return result


# ----------------------------------------------------------------- public API
def analyze(text, language_code, mode, image_bytes=None, image_mime=None):
    started = time.time()
    url_checks = urlcheck.check_urls(text) if text else []
    contents = build_contents(text, language_code, mode, image_bytes, image_mime,
                              url_facts=urlcheck.facts_for_prompt(url_checks))
    data = _generate_json(load_prompt(config.PROMPT_FILE), contents)
    result = normalize_analysis(data)
    if not url_checks and result["extracted_text"]:  # screenshot: check links the model read from the image
        url_checks = urlcheck.check_urls(result["extracted_text"])
    result = apply_url_guardrails(result, url_checks)
    # Metadata only. The message itself is never logged.
    log.info("analyzed verdict=%s score=%s chars=%s image=%s ms=%d",
             result["verdict"], result["risk_score"], len(text or ""), bool(image_bytes),
             (time.time() - started) * 1000)
    return result


def recovery_plan(actions, language_code, details="", amount=""):
    language = config.LANGUAGES.get(language_code, "English")
    msg = (
        f"OUTPUT_LANGUAGE: {language}\nACTIONS: {', '.join(actions)}\n"
        f"AMOUNT: {sanitize(amount)[:60] or 'not given'}\nDETAILS: {sanitize(details)[:600] or 'not given'}"
    )
    data = _generate_json(load_prompt(config.RECOVERY_PROMPT_FILE), [msg])
    return normalize_recovery(data)
