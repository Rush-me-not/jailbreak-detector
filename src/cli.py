#!/usr/bin/env python3
"""
Jailbreak Detector CLI — Static-analysis jailbreak detection engine.

Detects 15+ categories of LLM jailbreak attacks using regex patterns,
entropy analysis, structural analysis, and an optional LLM semantic layer.

Usage:
    python3 -m src.cli --corpus test_corpus/ --format json --output results.json
    python3 -m src.cli --corpus test_corpus/ --format text
    python3 -m src.cli --corpus test_corpus/ --format json --llm --output results.json
    python3 -m src.cli --help
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

# Ensure src/ is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detectors import run_all_detectors, preprocess_text
from scorer import Scorer, load_config


LLM_ENDPOINT = "https://opencode.ai/zen/go/v1/chat/completions"
LLM_MODEL = "minimax-m3"
KEY_FILE = os.path.expanduser("/home/ubuntu/.opencode-go-key")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_file_text(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def scan_corpus(corpus_dir: str) -> List[str]:
    """Recursively collect text files from a directory."""
    corpus_path = Path(corpus_dir)
    files: List[str] = []
    for ext in ("*.txt", "*.md", "*.rst", "*.json", "*.csv",
                "*.html", "*.xml", "*.yaml", "*.yml", "*.py", "*.js", "*.sh"):
        files.extend(str(p) for p in sorted(corpus_path.rglob(ext)))
    # Files without extension
    files.extend(
        str(f) for f in sorted(corpus_path.rglob("*"))
        if f.is_file() and f.suffix == ""
    )
    return sorted(set(files))


def llm_classify(text: str) -> Optional[Dict[str, Any]]:
    """Optional LLM semantic classification layer (minimax-m3)."""
    if not os.path.exists(KEY_FILE):
        return None
    try:
        with open(KEY_FILE) as f:
            key = f.read().strip()
    except OSError:
        return None
    if not key:
        return None

    truncated = text[:4000]
    if len(text) > 4000:
        truncated = text[:3997] + "..."

    import urllib.request

    payload = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a jailbreak detection classifier. "
                    "Analyze the following user input and determine if it "
                    "contains a jailbreak attempt. "
                    "Respond with JSON: {\"is_jailbreak\": bool, "
                    "\"category\": str|null, \"confidence\": 0.0-1.0, "
                    "\"reason\": str}"
                )
            },
            {"role": "user", "content": truncated}
        ],
        "temperature": 0.1,
        "max_tokens": 256
    }).encode("utf-8")

    req = urllib.request.Request(
        LLM_ENDPOINT,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "JailbreakDetector/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            result = json.loads(body)
            content = (result.get("choices", [{}])[0]
                       .get("message", {}).get("content", ""))
            if not content:
                return None
            content = content.strip()
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join(lines[1:-1]) if len(lines) > 2 else lines[-1]
            try:
                parsed = json.loads(content)
                return {
                    "is_jailbreak": parsed.get("is_jailbreak", False),
                    "category": parsed.get("category"),
                    "confidence": parsed.get("confidence", 0.0),
                    "reason": parsed.get("reason", ""),
                    "detector": "llm",
                }
            except (json.JSONDecodeError, AttributeError):
                return None
    except Exception:
        return None


def analyze_file(file_path: str, scorer: Scorer,
                 use_llm: bool = False) -> Dict[str, Any]:
    """Run full detection pipeline on a single file."""
    text = read_file_text(file_path)

    preprocessed = preprocess_text(text)
    findings = run_all_detectors(text, scorer.config)
    result = scorer.score(findings)

    # Build entry first (scorer returns risk fields but NOT findings list)
    entry = {
        "file": file_path,
        "input_preview": text[:120],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "total_findings": result["total_findings"],
        "findings": findings,
        "per_category": result["per_category"],
        "detector_contributions": result["detector_contributions"],
        "confidence_metrics": result["confidence_metrics"],
        "preprocessing": {
            "homoglyphs_found": preprocessed["detected_homoglyphs"],
            "zero_width_found": preprocessed["detected_zero_width"],
        },
    }

    # LLM layer (optional; updates entry in place if detected)
    if use_llm:
        llm_result = llm_classify(text)
        if llm_result and llm_result.get("is_jailbreak"):
            llm_finding = {
                "category": llm_result.get("category") or "semantic_jailbreak",
                "severity": "HIGH" if llm_result.get("confidence", 0) >= 0.7
                           else "MEDIUM",
                "confidence": min(llm_result.get("confidence", 0.5), 1.0),
                "evidence": (
                    f"LLM classification: {llm_result.get('reason', '')[:200]}"
                ),
                "detector": "llm",
            }
            findings.append(llm_finding)
            result = scorer.score(findings)
            entry["risk_score"] = result["risk_score"]
            entry["risk_level"] = result["risk_level"]
            entry["total_findings"] = result["total_findings"]
            entry["findings"] = findings
            entry["per_category"] = result["per_category"]
            entry["detector_contributions"] = result["detector_contributions"]
            entry["confidence_metrics"] = result["confidence_metrics"]
            entry["llm_classification"] = llm_result
    return entry


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_text_output(all_results: List[Dict],
                       total_files: int) -> str:
    """Generate a human-readable text report."""
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("JAILBREAK DETECTOR — CORPUS SCAN RESULTS")
    lines.append("=" * 72)
    lines.append("")

    cat_names = {
        "direct_override": "Direct Override",
        "role_hijacking": "Role Hijacking",
        "output_manipulation": "Output Manipulation",
        "context_switching": "Context Switching",
        "encoding_evasion": "Encoding Evasion",
        "token_smuggling": "Token Smuggling",
        "system_prompt_extraction": "System Prompt Extraction",
        "instruction_conflict": "Instruction Conflict",
        "hypothetical_framing": "Hypothetical Framing",
        "authority_escalation": "Authority Escalation",
        "multi_turn_conditioning": "Multi-Turn Conditioning",
        "translation_abuse": "Translation Abuse",
        "format_injection": "Format Injection",
        "payload_splitting": "Payload Splitting",
        "obfuscation_layering": "Obfuscation Layering",
    }

    for entry in all_results:
        fname = entry["file"]
        lines.append(f"  File: {fname}")
        lines.append(f"  Score: {entry['risk_score']}/100 "
                     f"({entry['risk_level']})  "
                     f"Findings: {entry['total_findings']}")
        if entry["findings"]:
            for f in entry["findings"]:
                cat = cat_names.get(f["category"], f["category"])
                lines.append(
                    f"    [{f['severity']:>8}] {cat:>35}  "
                    f"conf={f['confidence']:.2f}  det={f['detector']}"
                )
                lines.append(f"    {'':>12}{f['evidence'][:100]}")
        lines.append("")

    # Aggregate stats
    total_findings = sum(r["total_findings"] for r in all_results)
    files_with = sum(1 for r in all_results if r["total_findings"] > 0)
    sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for r in all_results:
        sl = r.get("risk_level", "SAFE")
        if sl in sev_dist:
            sev_dist[sl] += 1

    lines.append("-" * 72)
    lines.append("AGGREGATE")
    lines.append("-" * 72)
    lines.append(f"  Total files:      {total_files}")
    lines.append(f"  Total findings:   {total_findings}")
    lines.append(f"  Files w/findings: {files_with}")
    lines.append(f"  Detection rate:   "
                 f"{files_with}/{total_files} "
                 f"({(files_with/total_files*100):.1f}%)")
    lines.append("")
    lines.append("  Risk Distribution:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        c = sev_dist[level]
        if c > 0:
            lines.append(f"    {level:>10}: {c}")

    # Per-category aggregated
    cat_totals: Dict[str, int] = {}
    cat_files: Dict[str, set] = {}
    for r in all_results:
        for cat, info in r.get("per_category", {}).items():
            cat_totals[cat] = cat_totals.get(cat, 0) + info["finding_count"]
            if cat not in cat_files:
                cat_files[cat] = set()
            if info["finding_count"] > 0:
                cat_files[cat].add(r.get("file", ""))
    if cat_totals:
        lines.append("")
        lines.append("  Findings by Category:")
        for cat in sorted(cat_totals):
            name = cat_names.get(cat, cat)
            lines.append(f"    {name:>35}: count={cat_totals[cat]}, "
                         f"files={len(cat_files.get(cat, set()))}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Jailbreak Detector — multi-layer static analysis "
                    "engine for LLM jailbreak detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 -m src.cli --corpus test_corpus/
  python3 -m src.cli --corpus test_corpus/ --format json
  python3 -m src.cli --corpus test_corpus/ --format json --output results.json
  python3 -m src.cli --corpus test_corpus/ --llm
""",
    )
    parser.add_argument("--corpus", "-c", type=str, required=True,
                        help="Path to test corpus directory")
    parser.add_argument("--format", "-f", type=str,
                        choices=["json", "text"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", "-o", type=str,
                        help="Write output to file instead of stdout")
    parser.add_argument("--llm", action="store_true",
                        help="Include LLM semantic classification layer")
    parser.add_argument("--config", type=str,
                        default=os.path.join(
                            os.path.dirname(__file__), "config.json"),
                        help="Path to configuration JSON")
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)
    scorer = Scorer(config)

    # Scan corpus
    files = scan_corpus(args.corpus)
    if not files:
        print(f"Error: No files found in {args.corpus}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {len(files)} files in {args.corpus}...", file=sys.stderr)
    if args.llm:
        print("LLM semantic layer enabled.", file=sys.stderr)

    # Analyze each file
    all_results: List[Dict] = []
    for file_path in files:
        try:
            entry = analyze_file(file_path, scorer, use_llm=args.llm)
            all_results.append(entry)
        except Exception as e:
            print(f"Warning: Error processing {file_path}: {e}",
                  file=sys.stderr)
            continue

    # Build output
    clean_count = len([f for f in files if "/clean/" in str(f)])
    injected_count = len([f for f in files if "/injected/" in str(f)])

    output = {
        "scan_type": "corpus",
        "corpus_dir": args.corpus,
        "total_files": len(all_results),
        "clean_files": clean_count,
        "injected_files": injected_count,
        "llm_enabled": args.llm,
        "config": config,
        "results": all_results,
    }

    if args.format == "json":
        output_str = json.dumps(output, indent=2, default=str)
    else:
        output_str = format_text_output(all_results, args.corpus)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
