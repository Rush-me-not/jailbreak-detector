# Case Study — Multi-Layer Static Analysis for LLM Jailbreak Detection

What it does: screens text inputs for LLM jailbreak attempts before they reach the model. 15 attack categories, 3 detection layers, weighted scoring.

Why it matters: Most jailbreak detection tools are single-layer regex matchers. Attackers use encoding (base64, hex, ROT13), homoglyph substitution, zero-width chars, leetspeak, and structural injection — all of which bypass simple pattern matching. Organizations deploying LLMs need static-analysis tools that screen prompts at the gateway, not after the fact.

Architecture:
— RegexDetector: 70+ compiled patterns across 15 categories
— EntropyDetector: Shannon entropy, base64/hex/ROT13, homoglyph/zero-width/leetspeak detection
— StructuralDetector: delimiter density, nesting, role boundary markers, whitespace analysis
— WeightedScorer: configurable weights (0.4/0.3/0.3), confidence calibration, Shapley-style contributions
— Optional LLM layer: minimax-m3 semantic classification via opencode-go

Results: 15/15 injected files detected (100%). 5/11 clean files had false positives (all scored SAFE under 12). 37 findings across 14 categories. Average detector contribution: regex 29%, entropy 10%, structural 8%.

The hardest engineering challenge: tuning confidence calibration so that cross-validated findings (flagged by 2+ detectors) carry more weight than single-detector noise. Implementation: 1.2x boost for agreement, 0.85x penalty for solo findings.

Built with Python 3.11 stdlib — zero PyPI dependencies for the core engine. The LLM layer uses urllib.request only. 1,582 lines of source code across 4 modules.

This is not a tutorial clone. The multi-layer approach with confidence calibration and ablation analysis reflects real threat modeling for production AI security deployments.
