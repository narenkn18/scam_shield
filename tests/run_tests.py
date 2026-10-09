"""Run the labelled test cases against a prompt version and report accuracy.

Usage (from the project root, with GEMINI_API_KEY set):
    python tests/run_tests.py                                  # final prompt (prompts/system_prompt.txt)
    python tests/run_tests.py --prompt prompts/v1_basic.txt
    python tests/run_tests.py --prompt prompts/v2_structured.txt
Results are saved to tests/results/<prompt-name>.json so you can compare versions.
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import analyzer  # noqa: E402
import urlcheck  # noqa: E402


def extract_verdict(raw):
    """Pull SAFE / SUSPICIOUS / SCAM out of JSON output, or from the first keyword in free text."""
    try:
        data = analyzer.parse_json(raw)
        v = str(data.get("verdict", "")).upper()
        if v in analyzer.VERDICTS:
            return v
    except Exception:
        pass
    m = re.search(r"\b(SAFE|SUSPICIOUS|SCAM)\b", raw.upper())
    return m.group(1) if m else "UNPARSEABLE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="prompts/system_prompt.txt")
    ap.add_argument("--delay", type=float, default=4.0, help="seconds between calls (free-tier rate limits)")
    args = ap.parse_args()

    prompt_path = ROOT / args.prompt
    prompt = prompt_path.read_text(encoding="utf-8")
    json_mode = "valid json" in prompt.lower()
    cases = json.loads((ROOT / "tests" / "test_cases.json").read_text(encoding="utf-8"))

    print(f"Prompt: {args.prompt} | JSON mode: {json_mode} | cases: {len(cases)}\n")
    rows, correct = [], 0
    missed_scams = false_alarms = 0
    for i, case in enumerate(cases):
        facts = urlcheck.facts_for_prompt(urlcheck.check_urls(case["text"], use_safe_browsing=False))
        contents = analyzer.build_contents(case["text"], "en", "simple", url_facts=facts)
        try:
            raw = analyzer.raw_generate(prompt, contents, json_mode=json_mode)
            got = extract_verdict(raw)
        except analyzer.AnalyzerError as e:
            raw, got = f"ERROR: {e.message}", "ERROR"
        ok = got == case["expected"]
        correct += ok
        if case["expected"] in ("SCAM", "SUSPICIOUS") and got == "SAFE":
            missed_scams += 1
        if case["expected"] == "SAFE" and got in ("SCAM", "SUSPICIOUS"):
            false_alarms += 1
        rows.append({"id": case["id"], "category": case["category"], "expected": case["expected"],
                     "got": got, "ok": ok, "raw": raw})
        print(f"{'PASS' if ok else 'FAIL'}  {case['id']:<26} expected={case['expected']:<10} got={got}")
        if i < len(cases) - 1:
            time.sleep(args.delay)

    total = len(cases)
    print(f"\nAccuracy: {correct}/{total} ({100 * correct / total:.0f}%)")
    print(f"Dangerous misses (scam or suspicious marked SAFE): {missed_scams}")
    print(f"False alarms (legitimate marked SCAM or SUSPICIOUS): {false_alarms}")

    out_dir = ROOT / "tests" / "results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / (prompt_path.stem + ".json")
    out.write_text(json.dumps({
        "prompt": args.prompt, "model": analyzer.config.MODEL, "accuracy": f"{correct}/{total}",
        "dangerous_misses": missed_scams, "false_alarms": false_alarms, "results": rows,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
