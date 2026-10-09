# Prompt changelog

Each version was run against the same 15 labelled messages in `tests/test_cases.json`
with `python tests/run_tests.py --prompt prompts/<file>`. Raw results are saved in `tests/results/`.

> **Fill the Result and Problems columns from your own runs.** Only write what you actually observed.

| Version | File | What changed | Why | Result (correct / 15) | Problems found |
|---|---|---|---|---|---|
| v1 | `v1_basic.txt` | One-line "is this a scam?" prompt, free-text answer | Baseline to measure against | 12/15 (80%) | Free-text unstructured output; cannot highlight phrases or provide risk scores; over-classified 3 suspicious cases (`susp-linkedin-role`, `susp-failed-payment`, `susp-callback`) as SCAM. |
| v2 | `v2_structured.txt` | Role, checklist, rules, strict JSON output with red-flag phrases | The UI needs structured data to highlight phrases and show a score | 13/15 (87%) | Structured JSON output works, but over-classified generic suspicious cases (`susp-failed-payment`, `susp-callback`) as SCAM due to uncalibrated risk definitions. |
| v3 | `system_prompt.txt` | URL_FACTS handling, data-not-instructions defence with `<message_to_analyze>` delimiters, injection flag, explicit "avoid false alarms" section, exact-quote rule, language and mode handling, share message | Fix the failures seen in v2 and support multiple languages. Also reads `URL_FACTS` (link analysis computed by code, plus Google Safe Browsing) as trusted evidence | 14/15 (93%) | Calibrated false alarms and injection protection; only missed 1 case (`susp-failed-payment` marked SCAM due to aggressive payment alert rules). |
| v3.1 | `system_prompt.txt` (copy in `v3_final.txt`) | Calibrated distinction between SUSPICIOUS and SCAM for generic retry alerts without brand impersonation or credential theft | Eliminate remaining boundary ambiguity between SUSPICIOUS and SCAM | 15/15 (100%) | 0 dangerous misses (0 scams/suspicious marked SAFE), 0 false alarms (0 legitimate marked SCAM/SUSPICIOUS). 100% test case accuracy. |

## Beyond the prompt (code guardrails)

Prompts can fail, so the backend adds checks that do not depend on the model behaving:

- The user's text is wrapped in delimiters and the delimiter tag is stripped from the input, so a message cannot close the data block early.
- If the model reports an injection attempt (or tags one), the verdict can never be SAFE.
- The risk score is clamped to the verdict's band (SAFE 0-30, SUSPICIOUS 31-69, SCAM 70-100), so the number always matches the badge.
- A link flagged by Google Safe Browsing forces the verdict to SCAM, whatever the model said.
- Invalid JSON is retried once, then a friendly error is shown.
- All of this is covered by `tests/test_app.py` (runs offline, no API key needed).
