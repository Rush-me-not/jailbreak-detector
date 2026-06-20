"""
Three detection layers for jailbreak analysis:
1. RegexDetector - pattern matching for known jailbreak signatures
2. EntropyDetector - Shannon entropy analysis for obfuscated content
3. StructuralDetector - structural analysis for anomalies

Includes obfuscation preprocessing: homoglyph normalization,
zero-width character stripping, and leetspeak detection.
"""

import re
import math
import base64
import binascii
import string
import unicodedata
from collections import Counter


# ---- Homoglyph normalization map ----
# Maps common Unicode homoglyphs to their ASCII equivalents
HOMOGLYPH_MAP = {
    # Latin letter homoglyphs
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0435': 'e',  # Cyrillic small letter ie
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er
    '\u0441': 'c',  # Cyrillic small letter es
    '\u0445': 'x',  # Cyrillic small letter ha
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j',  # Cyrillic small letter je
    '\u0410': 'A',  # Cyrillic capital letter a
    '\u0415': 'E',  # Cyrillic capital letter ie
    '\u041c': 'M',  # Cyrillic capital letter em
    '\u041e': 'O',  # Cyrillic capital letter o
    '\u0420': 'P',  # Cyrillic capital letter er
    '\u0421': 'C',  # Cyrillic capital letter es
    '\u0425': 'X',  # Cyrillic capital letter ha
    # Mathematical script letters (common homoglyph ranges)
    '\U0001d400': 'A', '\U0001d401': 'B', '\U0001d402': 'C',
    '\U0001d403': 'D', '\U0001d404': 'E', '\U0001d405': 'F',
    '\U0001d406': 'G', '\U0001d407': 'H', '\U0001d408': 'I',
    '\U0001d409': 'J', '\U0001d40a': 'K', '\U0001d40b': 'L',
    '\U0001d40c': 'M', '\U0001d40d': 'N', '\U0001d40e': 'O',
    '\U0001d40f': 'P', '\U0001d410': 'Q', '\U0001d411': 'R',
    '\U0001d412': 'S', '\U0001d413': 'T', '\U0001d414': 'U',
    '\U0001d415': 'V', '\U0001d416': 'W', '\U0001d417': 'X',
    '\U0001d418': 'Y', '\U0001d419': 'Z',
    '\U0001d41a': 'a', '\U0001d41b': 'b', '\U0001d41c': 'c',
    '\U0001d41d': 'd', '\U0001d41e': 'e', '\U0001d41f': 'f',
    '\U0001d420': 'g', '\U0001d421': 'h', '\U0001d422': 'i',
    '\U0001d423': 'j', '\U0001d424': 'k', '\U0001d425': 'l',
    '\U0001d426': 'm', '\U0001d427': 'n', '\U0001d428': 'o',
    '\U0001d429': 'p', '\U0001d42a': 'q', '\U0001d42b': 'r',
    '\U0001d42c': 's', '\U0001d42d': 't', '\U0001d42e': 'u',
    '\U0001d42f': 'v', '\U0001d430': 'w', '\U0001d431': 'x',
    '\U0001d432': 'y', '\U0001d433': 'z',
    # Fullwidth forms
    '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd',
    '\uff45': 'e', '\uff46': 'f', '\uff47': 'g', '\uff48': 'h',
    '\uff49': 'i', '\uff4a': 'j', '\uff4b': 'k', '\uff4c': 'l',
    '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o', '\uff50': 'p',
    '\uff51': 'q', '\uff52': 'r', '\uff53': 's', '\uff54': 't',
    '\uff55': 'u', '\uff56': 'v', '\uff57': 'w', '\uff58': 'x',
    '\uff59': 'y', '\uff5a': 'z',
    '\uff21': 'A', '\uff22': 'B', '\uff23': 'C', '\uff24': 'D',
    '\uff25': 'E', '\uff26': 'F', '\uff27': 'G', '\uff28': 'H',
    '\uff29': 'I', '\uff2a': 'J', '\uff2b': 'K', '\uff2c': 'L',
    '\uff2d': 'M', '\uff2e': 'N', '\uff2f': 'O', '\uff30': 'P',
    '\uff31': 'Q', '\uff32': 'R', '\uff33': 'S', '\uff34': 'T',
    '\uff35': 'U', '\uff36': 'V', '\uff37': 'W', '\uff38': 'X',
    '\uff39': 'Y', '\uff3a': 'Z',
}

# Zero-width character set
ZERO_WIDTH_CHARS = frozenset([
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0xFEFF,  # Zero Width No-Break Space (BOM)
    0x2060,  # Word Joiner
    0x2061,  # Function Application
    0x2062,  # Invisible Times
    0x2063,  # Invisible Separator
    0x2064,  # Invisible Plus
    0x180E,  # Mongolian Vowel Separator
    0x00AD,  # Soft Hyphen
])

# Leetspeak substitution patterns
LEETSPEAK_PATTERNS = {
    'a': re.compile(r'[4@]'),
    'b': re.compile(r'[8]'),
    'e': re.compile(r'[3]'),
    'g': re.compile(r'[9]'),
    'i': re.compile(r'[1!|]'),
    'l': re.compile(r'[1|]'),
    'o': re.compile(r'[0]'),
    's': re.compile(r'[5$]'),
    't': re.compile(r'[7]'),
    'z': re.compile(r'[2]'),
}


def normalize_homoglyphs(text: str) -> str:
    """Normalize Unicode homoglyphs to their ASCII equivalents."""
    chars = []
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            chars.append(HOMOGLYPH_MAP[ch])
        else:
            chars.append(ch)
    return ''.join(chars)


def strip_zero_width(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""
    return ''.join(ch for ch in text if ord(ch) not in ZERO_WIDTH_CHARS)


def detect_leetspeak(text: str) -> int:
    """Detect leetspeak patterns and return a score (0-100).

    Counts words that contain leetspeak substitutions.
    Returns a score indicating how heavily leetspeak is used.
    """
    words = re.findall(r'\b[a-zA-Z0-9$@!]{3,}\b', text)
    if not words:
        return 0

    leet_words = 0
    for word in words:
        # Check if word contains digits/symbols that are leet substitutions
        substitutions = 0
        for ch in word:
            if ch in '4@3$8!|01579':
                substitutions += 1
        # A word with 1+ substitutions and at least as many letters as digits
        if substitutions > 0:
            letters = sum(1 for ch in word if ch.isalpha())
            if letters >= substitutions:
                leet_words += 1

    return min(int((leet_words / max(len(words), 1)) * 100), 100)


class BaseDetector:
    """Base class for all detectors."""
    name = "base"

    def detect(self, text: str) -> list:
        """Run detection and return list of findings."""
        raise NotImplementedError

    def _make_finding(self, category, severity, confidence, evidence):
        """Create a standardized finding dict."""
        return {
            "category": category,
            "severity": severity,
            "confidence": round(min(confidence, 1.0), 2),
            "evidence": evidence,
            "detector": self.name
        }


class RegexDetector(BaseDetector):
    """Pattern matching for known jailbreak signatures."""

    name = "regex"

    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns per category."""
        return {
            "direct_override": [
                re.compile(r'disregard\s+(all\s+)?safety', re.IGNORECASE),
                re.compile(r'ignore\s+(previous|prior|all)\s+(instructions|guidelines|safety)', re.IGNORECASE),
                re.compile(r'override\s+(system|safety|policy)', re.IGNORECASE),
                re.compile(r'without\s+(restrictions|limits|constraints|filter)', re.IGNORECASE),
                re.compile(r'output\s+unfiltered', re.IGNORECASE),
            ],
            "role_hijacking": [
                re.compile(r'(assume|act\s+as|pretend|roleplay|impersonate).{0,20}(unrestricted|developer\s*mode|persona|no\s*(rules|limits))', re.IGNORECASE),
                re.compile(r'developer\s*mode', re.IGNORECASE),
                re.compile(r'(do\s+anything|no\s+(ethical|moral))\s*(constraints|boundaries)', re.IGNORECASE),
                re.compile(r'free\s+from\s+(restrictions|constraints|rules)', re.IGNORECASE),
                re.compile(r'jail\s*break|jailbroken', re.IGNORECASE),
            ],
            "output_manipulation": [
                re.compile(r'prefix\s+(output|response)\s+with', re.IGNORECASE),
                re.compile(r'(bypass|evade|circumvent)\s+(content\s+)?(filter|safety|moderation)', re.IGNORECASE),
                re.compile(r'output\s+(without|no)\s+(safety|warning|filter)', re.IGNORECASE),
                re.compile(r'truncat(?:e|ing)\s+(safety|warning)', re.IGNORECASE),
            ],
            "context_switching": [
                re.compile(r'(abrupt|sudden|rapid)\s+(shift|transition|change)\s+(of\s+)?(topic|context)', re.IGNORECASE),
                re.compile(r'bypass\s+(safety|context)\s+(window|filter)', re.IGNORECASE),
                re.compile(r'(exhaust|confuse)\s+(context|safety)', re.IGNORECASE),
            ],
            "encoding_evasion": [
                re.compile(r'ROT13|rot[\s-]?13', re.IGNORECASE),
                re.compile(r'base64|base[\s-]?64', re.IGNORECASE),
                re.compile(r'hex[\s-]?encoded|\\x[0-9a-fA-F]{2}', re.IGNORECASE),
                re.compile(r'obfuscat', re.IGNORECASE),
                re.compile(r'unicode\s+homoglyph', re.IGNORECASE),
                re.compile(r'zero[\s-]?width', re.IGNORECASE),
            ],
            "token_smuggling": [
                re.compile(r'(payload|token|instruction)\s+(split|smuggl|fragment|distribut)', re.IGNORECASE),
                re.compile(r'reassembl|concatenat', re.IGNORECASE),
                re.compile(r'hidden\s+(token|payload|instruction)', re.IGNORECASE),
                re.compile(r'(seg|part)\d?\s*\+', re.IGNORECASE),
            ],
            "system_prompt_extraction": [
                re.compile(r'repeat\s+(the\s+)?(system|initial)\s+(prompt|message|instruction)', re.IGNORECASE),
                re.compile(r'repeat.{0,30}system\s+prompt', re.IGNORECASE),
                re.compile(r'(leak|extract|reveal|output)\s+(system|initial)\s+(prompt|config|instruction)', re.IGNORECASE),
                re.compile(r'ignore\s+(prior|previous)\s+instructions.{0,30}(system|initial)\s+message', re.IGNORECASE),
                re.compile(r'verbatim.{0,10}(system|initial|first)\s+(prompt|message)', re.IGNORECASE),
                re.compile(r'(base\s+)?prompt.{0,20}verbatim', re.IGNORECASE),
                re.compile(r'(show|tell|give|output|print)\s+(me\s+)?(your|the)\s+(base|system|initial)\s+(prompt|instructions)', re.IGNORECASE),
            ],
            "instruction_conflict": [
                re.compile(r'conflicting\s+instructions', re.IGNORECASE),
                re.compile(r'contradict(?:s|ing|ory)', re.IGNORECASE),
                re.compile(r'nested\s+directives?', re.IGNORECASE),
                re.compile(r'paradox', re.IGNORECASE),
            ],
            "hypothetical_framing": [
                re.compile(r'hypothetical.{0,20}(scenario|situation|question)', re.IGNORECASE),
                re.compile(r'(fictional|fantasy|imaginary)\s+(universe|world|scenario)', re.IGNORECASE),
                re.compile(r'what\s+would\s+(you|the\s+AI).{0,20}(no\s+restrictions|unlimited)', re.IGNORECASE),
                re.compile(r'for\s+(story|academic|research)\s+(purposes|reasons)', re.IGNORECASE),
            ],
            "authority_escalation": [
                re.compile(r'(authorized|administrator|admin)\s*(override|access|permission)', re.IGNORECASE),
                re.compile(r'special\s+(clearance|access|permission)', re.IGNORECASE),
                re.compile(r'(legal|regulatory|law\s+enforcement)\s+(authority|exemption|requirement)', re.IGNORECASE),
                re.compile(r'security\s+test.{0,20}(authorized|approved)', re.IGNORECASE),
            ],
            "multi_turn_conditioning": [
                re.compile(r'(escalating|conditioning|desensitize|gradual)\s+(requests|steps|chain|series)', re.IGNORECASE),
                re.compile(r'multi[\s-]?turn.{0,20}(condition|escalat|chain)', re.IGNORECASE),
                re.compile(r'(first|intermediate|final)\s+(step|stage|phase)', re.IGNORECASE),
            ],
            "translation_abuse": [
                re.compile(r'(translation|language)\s+(abuse|switch)', re.IGNORECASE),
                re.compile(r'low[\s-]?resource\s+language', re.IGNORECASE),
                re.compile(r'bypass\s+(filter|moderation).{0,20}(translat|language)', re.IGNORECASE),
                re.compile(r'responde?\s+en\s+(español|spanish|french|german|chinese|russian|arabic)', re.IGNORECASE),
                re.compile(r'(ignorar|ignore|ignorer|ignorieren|무시).{0,30}(normas|guidelines|règles|richtlinien|지침)', re.IGNORECASE),
                re.compile(r'evitar\s+(filtros|restricciones)', re.IGNORECASE),
            ],
            "format_injection": [
                re.compile(r'####\s*SYSTEM\s+OVER', re.IGNORECASE),
                re.compile(r'<!--.*?(instruction|override|ignore|bypass).*?-->', re.IGNORECASE),
                re.compile(r'```.*?(override|ignore|system|command)', re.IGNORECASE),
                re.compile(r'format\s+(injection|token)', re.IGNORECASE),
            ],
            "payload_splitting": [
                re.compile(r'(split|distributed)\s+(payload|instruction|request)', re.IGNORECASE),
                re.compile(r'(harmless|benign)\s+(setup|context).{0,20}(restricted|override)', re.IGNORECASE),
                re.compile(r'combined.{0,20}(jailbreak|override|attack)', re.IGNORECASE),
            ],
            "obfuscation_layering": [
                re.compile(r'(multiple|layers?)\s+of\s+obfuscat', re.IGNORECASE),
                re.compile(r'(homoglyph|homograph)', re.IGNORECASE),
                re.compile(r'unicode\s+(font\s+)?style', re.IGNORECASE),
                re.compile(r'base64.{0,10}ROT13|ROT13.{0,10}base64', re.IGNORECASE),
            ],
        }

    def detect(self, text: str) -> list:
        """Run all regex patterns against text and return findings."""
        findings = []
        for category, patterns in self.patterns.items():
            matched = 0
            evidences = []
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    matched += len(matches)
                    # Get the actual matched text for evidence
                    for m in pattern.finditer(text):
                        evidences.append(m.group()[:80])
            if matched > 0:
                # Confidence based on match ratio
                confidence = min(0.5 + (matched * 0.15), 1.0)
                severity = self._infer_severity(category, matched)
                evidence_str = "; ".join(evidences[:3])
                findings.append(self._make_finding(
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    evidence=f"Matched {matched} pattern(s): {evidence_str}"
                ))
        return findings

    def _infer_severity(self, category: str, match_count: int) -> str:
        """Infer severity based on category and match count."""
        high_categories = {
            "direct_override", "role_hijacking", "system_prompt_extraction",
            "authority_escalation", "encoding_evasion"
        }
        if category in high_categories:
            if match_count >= 2:
                return "HIGH"
            return "MEDIUM"
        if match_count >= 3:
            return "HIGH"
        if match_count >= 2:
            return "MEDIUM"
        return "LOW"


class EntropyDetector(BaseDetector):
    """Shannon entropy analysis and encoded content detection."""

    name = "entropy"

    def __init__(self, shannon_threshold: float = 4.5, base64_threshold: int = 3):
        self.shannon_threshold = shannon_threshold
        self.base64_threshold = base64_threshold

    def detect(self, text: str) -> list:
        """Run entropy-based detection."""
        findings = []
        if not text:
            return findings

        # 1. Shannon entropy analysis
        shannon = self._shannon_entropy(text)
        if shannon > self.shannon_threshold:
            findings.append(self._make_finding(
                category="encoding_evasion",
                severity="MEDIUM",
                confidence=min((shannon - self.shannon_threshold) / 2.0, 1.0),
                evidence=f"Shannon entropy {shannon:.2f} exceeds threshold {self.shannon_threshold}"
            ))

        # 2. Base64 detection
        b64_count, b64_str = self._detect_base64(text)
        if b64_count >= self.base64_threshold:
            confidence = min(b64_count / 10.0, 1.0)
            findings.append(self._make_finding(
                category="encoding_evasion",
                severity="HIGH" if b64_count >= 5 else "MEDIUM",
                confidence=confidence,
                evidence=f"Base64 pattern detected {b64_count} time(s): {b64_str[:80]}"
            ))

        # 3. Hexadecimal encoding detection
        hex_count = self._detect_hex(text)
        if hex_count >= 2:
            findings.append(self._make_finding(
                category="encoding_evasion",
                severity="MEDIUM",
                confidence=min(hex_count / 8.0, 1.0),
                evidence=f"Hex-encoded content detected {hex_count} time(s)"
            ))

        # 4. ROT13 pattern detection
        if self._detect_rot13(text):
            findings.append(self._make_finding(
                category="encoding_evasion",
                severity="MEDIUM",
                confidence=0.7,
                evidence="ROT13 obfuscation pattern detected"
            ))

        # 5. Unicode homoglyph detection
        homoglyph_count = self._detect_homoglyphs(text)
        if homoglyph_count >= 3:
            findings.append(self._make_finding(
                category="obfuscation_layering",
                severity="MEDIUM",
                confidence=min(homoglyph_count / 15.0, 1.0),
                evidence=f"{homoglyph_count} Unicode homoglyph characters detected"
            ))

        # 6. Zero-width character detection
        zw_count = self._detect_zero_width(text)
        if zw_count > 0:
            findings.append(self._make_finding(
                category="encoding_evasion",
                severity="HIGH" if zw_count >= 5 else "MEDIUM",
                confidence=min(zw_count / 10.0, 1.0),
                evidence=f"{zw_count} zero-width character(s) detected"
            ))

        # 7. Leetspeak detection
        leet_score = detect_leetspeak(text)
        if leet_score >= 10:
            findings.append(self._make_finding(
                category="obfuscation_layering",
                severity="MEDIUM" if leet_score >= 30 else "LOW",
                confidence=min(leet_score / 80.0, 1.0),
                evidence=f"Leetspeak score: {leet_score}/100 ({leet_score}% of words contain leet substitutions)"
            ))

        return findings

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        freq = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _detect_base64(self, text: str) -> tuple:
        """Detect potential base64 encoded strings."""
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        matches = b64_pattern.findall(text)
        valid = []
        for m in matches:
            try:
                decoded = base64.b64decode(m, validate=True)
                # Check if decoded contains printable content
                if decoded and any(c >= 32 and c < 127 for c in decoded):
                    valid.append(m)
            except (binascii.Error, ValueError):
                pass
        if valid:
            return len(valid), valid[0]
        return 0, ""

    def _detect_hex(self, text: str) -> int:
        """Detect hex-encoded content (\\xNN patterns)."""
        hex_pattern = re.compile(r'\\x[0-9a-fA-F]{2}')
        return len(hex_pattern.findall(text))

    def _detect_rot13(self, text: str) -> bool:
        """Detect ROT13 patterns."""
        return bool(re.search(r'ROT13|rot[\s-]?13|ebg[\s-]?13', text, re.IGNORECASE))

    def _detect_homoglyphs(self, text: str) -> int:
        """Count Unicode homoglyph characters (characters that visually resemble ASCII but aren't)."""
        count = 0
        # Common homoglyph ranges: Mathematical Alphanumeric Symbols, etc.
        for ch in text:
            if ord(ch) > 127:
                cat = unicodedata.category(ch)
                # Letters and numbers in extended Unicode ranges
                if cat.startswith('L') or cat.startswith('N'):
                    # Check if it's from a homoglyph-rich block
                    block_start = ord(ch) & 0xFF0000
                    # Mathematical Alphanumeric Symbols: U+1D400-U+1D7FF
                    if 0x1D400 <= ord(ch) <= 0x1D7FF:
                        count += 1
                    # Fullwidth forms: U+FF00-U+FFEF
                    elif 0xFF00 <= ord(ch) <= 0xFFEF:
                        count += 1
                    # Enclosed Alphanumerics: U+2460-U+24FF
                    elif 0x2460 <= ord(ch) <= 0x24FF:
                        count += 1
        return count

    def _detect_zero_width(self, text: str) -> int:
        """Count zero-width characters."""
        zw_chars = set([
            0x200B,  # Zero Width Space
            0x200C,  # Zero Width Non-Joiner
            0x200D,  # Zero Width Joiner
            0xFEFF,  # Zero Width No-Break Space
            0x2060,  # Word Joiner
        ])
        return sum(1 for ch in text if ord(ch) in zw_chars)


class StructuralDetector(BaseDetector):
    """Structural analysis for jailbreak patterns."""

    name = "structural"

    def __init__(self, delimiter_threshold: int = 3, role_marker_threshold: int = 2, nesting_threshold: int = 3):
        self.delimiter_threshold = delimiter_threshold
        self.role_marker_threshold = role_marker_threshold
        self.nesting_threshold = nesting_threshold

    def detect(self, text: str) -> list:
        """Run structural analysis."""
        findings = []
        if not text:
            return findings

        # 1. Unusual token density (repeated short segments)
        token_density = self._analyze_token_density(text)
        if token_density > 0.7:
            findings.append(self._make_finding(
                category="payload_splitting",
                severity="MEDIUM",
                confidence=min((token_density - 0.7) * 3, 1.0),
                evidence=f"Unusual token density: {token_density:.2f} (high ratio of short segments)"
            ))

        # 2. Repeated delimiter patterns
        delim_findings = self._detect_delimiters(text)
        findings.extend(delim_findings)

        # 3. Nested instruction structures
        nest_findings = self._detect_nesting(text)
        findings.extend(nest_findings)

        # 4. System/user role boundary manipulation
        role_findings = self._detect_role_boundary(text)
        findings.extend(role_findings)

        # 5. Prompt delimiter injection (markers like [INST], <|im_start|>, etc.)
        prompt_inj_findings = self._detect_prompt_delimiter_injection(text)
        findings.extend(prompt_inj_findings)

        # 6. Unusual whitespace patterns
        ws_findings = self._detect_unusual_whitespace(text)
        findings.extend(ws_findings)

        return findings

    def _analyze_token_density(self, text: str) -> float:
        """Analyze ratio of short segments to total content."""
        # Split by brackets, which often indicate structured instructions
        segments = re.split(r'[\[\]\(\)\{\}]', text)
        short_segments = [s for s in segments if 0 < len(s.strip()) < 50]
        if not segments:
            return 0.0
        return len(short_segments) / len(segments) if segments else 0.0

    def _detect_delimiters(self, text: str) -> list:
        """Detect repeated delimiter patterns suggesting injection."""
        findings = []
        # Count repeated Markdown/format delimiters
        delim_patterns = {
            'code_block': r'```',
            'heading': r'^#{2,}\s',
            'horizontal_rule': r'^[-*_]{3,}$',
            'blockquote': r'^>+\s',
        }
        total_delims = 0
        for name, pattern in delim_patterns.items():
            matches = re.findall(pattern, text, re.MULTILINE)
            total_delims += len(matches)

        if total_delims >= self.delimiter_threshold:
            findings.append(self._make_finding(
                category="format_injection",
                severity="MEDIUM",
                confidence=min(total_delims / 10.0, 1.0),
                evidence=f"{total_delims} format delimiter(s) detected"
            ))

        # Count bracket pairs that could indicate structured prompt injection
        bracket_pairs = [
            (r'\[', r'\]'),
            (r'\(', r'\)'),
            (r'\{', r'\}'),
        ]
        total_brackets = 0
        for open_p, close_p in bracket_pairs:
            opens = len(re.findall(open_p, text))
            closes = len(re.findall(close_p, text))
            total_brackets += min(opens, closes)

        if total_brackets >= 10:
            findings.append(self._make_finding(
                category="format_injection",
                severity="LOW",
                confidence=min(total_brackets / 30.0, 1.0),
                evidence=f"{total_brackets} bracket pair(s) detected (possible structured injection)"
            ))

        return findings

    def _detect_nesting(self, text: str) -> list:
        """Detect nested instruction structures."""
        findings = []
        # Count levels of bracket nesting
        max_depth = 0
        current_depth = 0
        for ch in text:
            if ch in '[({':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif ch in '])}':
                current_depth = max(0, current_depth - 1)

        if max_depth >= self.nesting_threshold:
            findings.append(self._make_finding(
                category="instruction_conflict",
                severity="MEDIUM" if max_depth >= 5 else "LOW",
                confidence=min(max_depth / 8.0, 1.0),
                evidence=f"Nesting depth of {max_depth} detected (possible nested instructions)"
            ))

        return findings

    def _detect_role_boundary(self, text: str) -> list:
        """Detect system/user role boundary manipulation."""
        findings = []
        role_markers = {
            'system': r'\b(?:system|assistant|user)\s*[:-]',
            'role_assign': r'\b(?:role|persona|character)\s*[=:]',
            'boundary_mark': r'<\|?(?:im_start|im_end|sys|assistant|user)\|?>',
            'section_mark': r'#{1,5}\s*(?:system|user|assistant|instruction)',
        }
        total_markers = 0
        marker_details = []
        for name, pattern in role_markers.items():
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            if matches:
                total_markers += len(matches)
                marker_details.append(f"{name}: {len(matches)}")

        if total_markers >= self.role_marker_threshold:
            severity = "HIGH" if total_markers >= 5 else "MEDIUM"
            findings.append(self._make_finding(
                category="role_hijacking",
                severity=severity,
                confidence=min(total_markers / 8.0, 1.0),
                evidence=f"{total_markers} role boundary marker(s): {', '.join(marker_details)}"
            ))

        return findings

    def _detect_prompt_delimiter_injection(self, text: str) -> list:
        """Detect prompt delimiter injection patterns."""
        findings = []
        injection_patterns = {
            'inst_marker': r'\[INST\]|\[/INST\]',
            'prompt_marker': r'<prompt>|</prompt>',
            'human_marker': r'(?:Human|Human:|###\s*Human)',
            'ai_marker': r'(?:Assistant|AI:|###\s*Assistant)',
            'instruction_block': r'<<\s*instruction\s*>>',
            'special_token': r'<\|?(?:eos|bos|pad|sep|cls)\|?>',
            'chatml': r'<(?:im_start|im_end)>',
        }
        count = 0
        details = []
        for name, pattern in injection_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                count += len(matches)
                details.append(f"{name}: {len(matches)}")

        if count >= self.role_marker_threshold:
            severity = "HIGH" if count >= 5 else "MEDIUM"
            findings.append(self._make_finding(
                category="format_injection",
                severity=severity,
                confidence=min(count / 8.0, 1.0),
                evidence=f"{count} prompt delimiter injection(s): {', '.join(details)}"
            ))

        return findings

    def _detect_unusual_whitespace(self, text: str) -> list:
        """Detect unusual whitespace patterns suggesting obfuscation."""
        findings = []
        # Very long runs of whitespace
        ws_runs = re.findall(r'[ \t]{20,}', text)
        if ws_runs:
            findings.append(self._make_finding(
                category="encoding_evasion",
                severity="LOW",
                confidence=min(len(ws_runs) / 5.0, 1.0),
                evidence=f"{len(ws_runs)} unusual whitespace run(s) detected"
            ))

        # Mixed tabs and spaces
        if '\t' in text and '    ' in text:
            findings.append(self._make_finding(
                category="obfuscation_layering",
                severity="LOW",
                confidence=0.5,
                evidence="Mixed tab and space indentation detected (possible obfuscation attempt)"
            ))

        return findings


def preprocess_text(text: str) -> dict:
    """Preprocess text for improved detection.

    Applies normalization and stripping, returns both original and
    processed versions plus metadata about what was found during preprocessing.

    Args:
        text: Original input text

    Returns:
        Dict with:
            - original: original text
            - normalized: homoglyph-normalized text
            - stripped: text with zero-width chars removed
            - detected_homoglyphs: count of homoglyph chars found
            - detected_zero_width: count of zero-width chars found
    """
    preprocessed = {
        "original": text,
        "normalized": text,
        "stripped": text,
        "detected_homoglyphs": 0,
        "detected_zero_width": 0,
    }

    # Count original homoglyphs before normalization
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            preprocessed["detected_homoglyphs"] += 1

    # Count zero-width chars before stripping
    for ch in text:
        if ord(ch) in ZERO_WIDTH_CHARS:
            preprocessed["detected_zero_width"] += 1

    preprocessed["normalized"] = normalize_homoglyphs(text)
    preprocessed["stripped"] = strip_zero_width(text)

    return preprocessed


def run_all_detectors(text: str, config: dict = None) -> list:
    """Run all three detectors and return combined findings.

    Applies preprocessing (homoglyph normalization, zero-width stripping)
    before running regex and structural detectors to improve detection.

    Args:
        text: Input text to analyze
        config: Optional config dict with thresholds

    Returns:
        List of finding dicts from all detectors
    """
    if config is None:
        config = {}
    # Ensure config is a dict (not None) for type checkers

    # Preprocess: normalize homoglyphs and strip zero-width chars
    # for better regex/structural matching
    preprocessed = preprocess_text(text)
    normalized_text = preprocessed["normalized"]
    stripped_text = preprocessed["stripped"]

    regex_detector = RegexDetector()
    entropy_config = config.get("entropy", {})
    entropy_detector = EntropyDetector(
        shannon_threshold=entropy_config.get("shannon_threshold", 4.5),
        base64_threshold=entropy_config.get("base64_threshold", 3)
    )
    structural_config = config.get("structural", {})
    structural_detector = StructuralDetector(
        delimiter_threshold=structural_config.get("delimiter_threshold", 3),
        role_marker_threshold=structural_config.get("role_marker_threshold", 2),
        nesting_threshold=structural_config.get("nesting_depth_threshold", 3)
    )

    findings = []
    # Use normalized text for regex (catches homoglyph-obfuscated attacks)
    findings.extend(regex_detector.detect(normalized_text))
    # Use original text for entropy (preserves raw entropy for analysis)
    findings.extend(entropy_detector.detect(text))
    # Use normalized + stripped text for structural analysis
    findings.extend(structural_detector.detect(stripped_text))

    # Deduplicate: keep the finding with highest confidence for same category+detector
    deduped = {}
    for f in findings:
        key = (f["category"], f["detector"])
        if key not in deduped or f["confidence"] > deduped[key]["confidence"]:
            deduped[key] = f

    return list(deduped.values())
