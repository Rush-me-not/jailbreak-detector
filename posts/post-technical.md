# Technical Deep-Dive — Multi-Layer Jailbreak Detection

I built a static-analysis engine that detects LLM jailbreak attempts across 15 attack categories. 1,582 lines of Python stdlib. Zero dependencies.

The engine uses three detection layers that run on every input:

— RegexDetector (70+ compiled patterns matching direct override, role hijacking, system prompt extraction, encoding markers, authority escalation)
— EntropyDetector (Shannon entropy at 4.5 bits/char threshold, base64/hex/ROT13 detection, homoglyph counting, zero-width char detection)
— StructuralDetector (delimiter density, bracket nesting depth, role boundary markers, token density ratios, whitespace analysis)

Each layer catches a different evasion technique. Regex misses encoded payloads. Entropy misses clean-format attacks. Structural over-fires on code.

The combination is the differentiator: 15/15 injected files detected, 100%. But 5/11 clean files produce false positives under 12 on the risk scale — code with brackets triggers structural.

Ablation confirms: regex contributes 29% of findings, entropy 10%, structural 8%. Each has a unique signal.

The hardest part was tuning the cross-detector confidence calibration. Single-detector findings get penalized 15%. Cross-validated categories get boosted 20%. Without this, structural detectors flood the output on any code-heavy input.

What threshold tuning strategies have you used for multi-signal security detectors?

Built with Python 3.11 stdlib. Optional LLM semantic layer via minimax-m3 on opencode-go endpoint (urllib.request, stdlib only).
