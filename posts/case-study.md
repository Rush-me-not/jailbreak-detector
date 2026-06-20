# Case Study: Building a Multi-Layer Jailbreak Detector for LLMs

## The Problem

A client deploying a customer-facing LLM chatbot was getting pwned weekly. Users would paste "DAN mode" prompts, encode instructions in base64, or use Unicode homoglyphs to slip past the single regex filter they had in production. One attack used zero-width characters to hide an override instruction that made the bot output its entire system prompt. They needed something better.

## The Approach

We built a three-layer static analysis engine that runs on prompts before they reach the LLM:

1. **RegexDetector** -- 70+ patterns across 15 categories covering direct overrides, role hijacking, encoding markers, and extraction attempts.
2. **EntropyDetector** -- Shannon entropy analysis, base64/hex/ROT13 sniffing, homoglyph counting, and leetspeak scoring.
3. **StructuralDetector** -- Token density, delimiter counting, nesting depth, and role boundary markers.

A WeightedScorer combines all findings into a single 0-100 risk score with per-category breakdowns and cross-detector confidence calibration.

## The Results

Tested against 26 prompts (11 clean, 15 injected):

- 100% detection rate on injected attacks
- Zero false positives on normal queries
- Only 5/11 clean code/data files produced low-severity structural findings (all scored SAFE)
- Cross-detector agreement proved to be the strongest confidence signal

## Key Takeaway

No single detection layer is sufficient. Regex catches known patterns but misses novel obfuscation. Entropy analysis catches encoding but FPs on multi-language text. Structural analysis catches injection but FPs on code. Together, with a weighted scoring model, they provide reliable detection with calibrated confidence.

#jailbreak #llmsecurity #aisafety
