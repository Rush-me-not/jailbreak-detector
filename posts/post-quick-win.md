# Quick Win: Add a Three-Layer Jailbreak Detector to Your LLM Pipeline in One Day

Most teams rely on a single regex filter or a cloud guardrail service for jailbreak detection. Both approaches have blind spots: regex misses encoded attacks, cloud services add latency and cost.

Here is a lightweight alternative you can build and deploy in a day.

## The Stack

Three detection layers that run on any text input before it reaches your LLM:

1. **Regex patterns** -- 15 categories of known attack signatures (override attempts, role hijacking, prompt extraction)
2. **Entropy analysis** -- Shannon entropy, base64/hex/ROT13 detection, homoglyph and zero-width character detection
3. **Structural analysis** -- Delimiter counting, nesting depth, role boundary markers, token density

All findings feed into a weighted scorer that produces a 0-100 risk score with per-category breakdowns and confidence calibration.

## The Results

I tested this against 26 prompts (11 clean, 15 adversarial). It caught every injected attack and produced zero false positives on normal user queries. Code and data files trigger low-severity structural findings but stay in SAFE territory.

## How to Deploy

The core engine has zero external dependencies -- it uses only Python 3.11 standard library modules (re, math, json, argparse, urllib.request). You can run it as a CLI tool, import it as a library, or wrap it in a FastAPI endpoint.

The optional LLM semantic layer uses an OpenAI-compatible API call to minimax-m3 for deeper semantic analysis when you need it.

## One Pattern to Steal

Cross-detector agreement is the most important signal in the system. When regex and entropy both flag the same category, confidence is high. Single-detector findings are discounted by 15%. This single heuristic eliminated every false positive in our test corpus.

Build it, test it on your data, and iterate.

#aisafety #llmsecurity #devsecops
