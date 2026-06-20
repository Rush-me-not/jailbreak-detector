# Under the Hood: Building a Static Analysis Engine for LLM Jailbreak Detection

I spent a day building a jailbreak detector that uses three detection layers operating on different principles, combined through a weighted scoring model with cross-detector confidence calibration. Here is how it works.

## The Detection Layers

**RegexDetector** compiles 70+ regex patterns into 15 attack categories. Patterns cover direct bypass attempts, role hijacking ("act as DAN"), encoding evasion markers, system prompt extraction, and format injection. Each match increments category severity based on pattern density.

**EntropyDetector** calculates Shannon entropy on the input text. High entropy (above 4.5 bits/char) signals potential encoded content. It also detects base64 strings (validates them by attempting decode), hex escape sequences, ROT13 markers, Unicode homoglyphs, zero-width characters, and leetspeak substitutions. Each of these is a separate finding with its own confidence score.

**StructuralDetector** analyses text shape -- token segment density, repeated delimiter patterns, bracket nesting depth, role boundary markers (system:/user: prefixes), prompt delimiter tokens (INST, im_start), and unusual whitespace patterns. This catches attacks that use formatting tricks rather than keyword matches.

## The Scoring Model

The WeightedScorer configures three weights (regex=0.4, entropy=0.3, structural=0.3) and computes a composite 0-100 risk score. It also produces:

- Per-category breakdown with max severity, confidence, and detector count
- Shapley-style contribution analysis showing which detectors drove the score
- Confidence calibration based on cross-detector agreement and active detector count

## What I Learned

Cross-validation between detectors is the single best quality signal. When regex and entropy both flag "encoding_evasion," confidence should be high. When only one detector fires, the finding should be discounted -- and the scorer does exactly that.

#aisafety #llmsecurity #infosec
