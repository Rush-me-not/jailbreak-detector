# Lessons Learned Building an LLM Jailbreak Detector

I built a multi-layer jailbreak detection engine over the past day and ran it against a test corpus of 26 prompts. Here are the five lessons that surprised me most.

## 1. Regex Alone Is Not Enough

The regex layer caught 80% of direct override and role hijacking attacks. But it completely missed encoded payloads -- base64 strings, hex sequences, ROT13 obfuscation. Attackers who use encoding will sail past a pure regex filter. You need entropy analysis alongside pattern matching.

## 2. Entropy False Positives Are Real

Shannon entropy is a great signal for encoded content, but multi-language text naturally has high entropy. One of our clean files -- a simple multi-language greeting -- triggered an entropy finding at 4.82 bits/char against a 4.5 threshold. A language-aware threshold would eliminate these false positives without sacrificing detection.

## 3. Structural Analysis Over-Fires on Code

Bracket counting, nesting depth, and token density are excellent signals for format injection and payload splitting. They also fire on any JSON file, Python script, or structured document. The scores stay in SAFE territory (<20) but the noise is real. A source-code whitelist or file-type-aware threshold is needed for production.

## 4. Cross-Detector Agreement Is the Best Confidence Signal

When regex and entropy both flag the same category (encoding_evasion on a base64 payload), confidence should be high. When only one detector fires, the scorer discounts the finding by 15%. This single mechanism eliminated all false positives on clean files.

## 5. The LLM Layer Adds Value but Has Trade-offs

The optional minimax-m3 semantic layer can catch attacks that no statistical method would find. But it requires an API key, adds latency, and scales with token volume. For high-throughput screening, the three static layers are sufficient for a first pass.

#llmsecurity #aisafety #sre
