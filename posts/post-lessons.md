# Lessons Learned — What Broke in a Multi-Layer Jailbreak Detector

Three things I got wrong building a 15-category jailbreak scanner:

1. Shannon entropy is a liar on multi-language text. The corpus has a file mixing English, Japanese, and Arabic — entropy measured 4.82 bits/char. My threshold was 4.5. False positive. The fix: only flag entropy when another detector also fires.

2. Structural analysis hates code. The bracket counter flags Python/JS files as "nested instruction structures" at depth 4+. On a 300-line algorithms.py, structural fired twice. The risk score stayed SAFE (11.3/100) because regex and entropy found nothing, and the confidence calibration penalized single-detector findings by 15%.

3. Cross-detector agreement is the only reliable confidence signal. Any finding from one detector alone gets a 0.85x multiplier. Findings validated by 2+ detectors get 1.2x. This single rule eliminated 80% of my false positive problem without sacrificing detection rate on real attacks.

The pattern that survived: preprocess inputs before detection. Homoglyph normalization maps Unicode lookalikes to ASCII. Zero-width stripping removes invisible injection chars. Leetspeak scoring flags character-substitution obfuscation.

The tool catches 15/15 injected test files. Detection rate is not the hard part. Keeping false positives below operational noise threshold is.
