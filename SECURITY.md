# Security

## Reporting a problem
Please open a private security advisory on GitHub, or contact the maintainer directly. Do not post secrets or exploits in public issues.

## What the app does to stay safe
- **Secrets:** `GEMINI_API_KEY` and `GOOGLE_SAFE_BROWSING_API_KEY` live only in `.env` (git-ignored) or the host's environment settings. They are never logged, returned to the browser or put in prompts.
- **Untrusted input:** messages are wrapped as data, delimiter tags are stripped from the input, and the model is told never to follow instructions inside them. A code guardrail means a message that tries to control the AI can never be returned as SAFE.
- **Output validation:** model output is parsed and type-checked, scores are clamped to the verdict, and invalid JSON is retried once.
- **Input limits:** message length, real image type (magic bytes) and size, per-IP and daily rate limits.
- **Browser:** strict Content-Security-Policy (no inline scripts), `nosniff`, no framing, no referrer, locked-down permissions policy, HSTS over HTTPS. Untrusted text is added with DOM text nodes, never `innerHTML`.
- **Privacy:** message text is not stored or logged. Messages and screenshots are sent to Google's Gemini API for analysis. Only extracted links (not message text) are sent to Google Safe Browsing, and only if a key is configured.

## Known limits
- The rate limiter is in memory, so on serverless hosting it is best-effort per instance. Set a quota on your API keys.
- The AI can be wrong. The app gives guidance, not a guarantee.
