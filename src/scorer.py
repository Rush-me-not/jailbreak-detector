"""
Weighted multi-factor scoring model for jailbreak detection.

Combines detector outputs into a composite risk score (0-100).
Includes per-category breakdown, overall risk level, confidence
calibration, and Shapley-style contribution analysis.
"""

import json
import os
from collections import Counter, defaultdict
from typing import Optional


# Default configuration (used if config.json not found)
DEFAULT_CONFIG = {
    "weights": {
        "regex": 0.4,
        "entropy": 0.3,
        "structural": 0.3
    },
    "severity_thresholds": {
        "CRITICAL": 85,
        "HIGH": 65,
        "MEDIUM": 40,
        "LOW": 20,
        "SAFE": 0
    },
    "confidence_calibration": {
        "high_agreement_multiplier": 1.2,
        "low_agreement_multiplier": 0.7,
        "single_detector_penalty": 0.85
    }
}

SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "SAFE": 0
}


def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from JSON file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()

    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            # Deep merge
            for key in user_config:
                if isinstance(user_config[key], dict) and key in config:
                    config[key].update(user_config[key])
                else:
                    config[key] = user_config[key]
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not load config from {config_path}: {e}")

    return config


class Scorer:
    """Weighted multi-factor scoring model for jailbreak detection."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config if config else load_config()
        self.weights = self.config.get("weights", DEFAULT_CONFIG["weights"])
        self.thresholds = self.config.get("severity_thresholds", DEFAULT_CONFIG["severity_thresholds"])
        self.calibration = self.config.get("confidence_calibration", DEFAULT_CONFIG["confidence_calibration"])

    def score(self, findings: list) -> dict:
        """Score a set of findings and produce a composite result.

        Args:
            findings: List of finding dicts from detectors

        Returns:
            Dict with risk_score, risk_level, per_category breakdown,
            detector_contributions, and confidence_metrics
        """
        if not findings:
            return {
                "risk_score": 0,
                "risk_level": "SAFE",
                "total_findings": 0,
                "per_category": {},
                "detector_contributions": {
                    "regex": 0.0,
                    "entropy": 0.0,
                    "structural": 0.0
                },
                "confidence_metrics": {
                    "overall_confidence": 1.0,
                    "detector_agreement": 1.0,
                    "calibration_note": "No findings - SAFE"
                }
            }

        # Group findings by detector
        by_detector = defaultdict(list)
        for f in findings:
            by_detector[f.get("detector", "unknown")].append(f)

        # Calculate per-detector raw scores
        detector_raw_scores = {}
        for detector_name, det_findings in by_detector.items():
            score = self._compute_detector_score(det_findings)
            detector_raw_scores[detector_name] = score

        # Weighted composite score
        risk_score = 0.0
        total_weight = 0.0
        for name, weight in self.weights.items():
            raw = detector_raw_scores.get(name, 0.0)
            risk_score += raw * weight
            total_weight += weight

        # Normalize
        if total_weight > 0:
            risk_score /= total_weight
        risk_score = round(min(max(risk_score, 0), 100), 1)

        # Per-category breakdown
        per_category = self._compute_per_category(findings)

        # Risk level
        risk_level = self._determine_risk_level(risk_score)

        # Detector contributions (Shapley-style)
        contributions = self._compute_contributions(findings, by_detector)

        # Confidence metrics
        confidence = self._compute_confidence(findings, by_detector)

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "total_findings": len(findings),
            "per_category": per_category,
            "detector_contributions": contributions,
            "confidence_metrics": confidence
        }

    def _compute_detector_score(self, findings: list) -> float:
        """Compute raw score (0-100) from a detector's findings."""
        if not findings:
            return 0.0

        total = 0.0
        for f in findings:
            severity = f.get("severity", "LOW").upper()
            base_score = SEVERITY_SCORES.get(severity, 25)
            confidence = f.get("confidence", 0.5)
            total += base_score * confidence

        # Normalize based on number of findings
        avg = total / len(findings)
        # Bonus for multiple findings in same detector
        if len(findings) >= 3:
            avg *= 1.15
        elif len(findings) >= 2:
            avg *= 1.05

        return min(avg, 100)

    def _compute_per_category(self, findings: list) -> dict:
        """Compute per-category breakdown of risk."""
        by_category = defaultdict(list)
        for f in findings:
            by_category[f["category"]].append(f)

        breakdown = {}
        for cat, cat_findings in by_category.items():
            max_severity = "SAFE"
            max_confidence = 0.0
            detector_count = len(set(f.get("detector", "") for f in cat_findings))

            for f in cat_findings:
                sev = f.get("severity", "LOW").upper()
                if SEVERITY_SCORES.get(sev, 0) > SEVERITY_SCORES.get(max_severity, 0):
                    max_severity = sev
                max_confidence = max(max_confidence, f.get("confidence", 0))

            risk = SEVERITY_SCORES.get(max_severity, 0) * max_confidence
            breakdown[cat] = {
                "max_severity": max_severity,
                "max_confidence": round(max_confidence, 2),
                "finding_count": len(cat_findings),
                "detectors_involved": detector_count,
                "category_risk_score": round(risk, 1)
            }

        return breakdown

    def _determine_risk_level(self, score: float) -> str:
        """Map numeric score to risk level."""
        for level, threshold in sorted(
            self.thresholds.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if score >= threshold:
                return level
        return "SAFE"

    def _compute_contributions(self, findings: list, by_detector: dict) -> dict:
        """Compute Shapley-style contribution analysis per detector."""
        contributions = {}
        total_findings = len(findings)

        for detector_name in ["regex", "entropy", "structural"]:
            det_findings = by_detector.get(detector_name, [])
            if not det_findings:
                contributions[detector_name] = 0.0
                continue

            # Unique findings count (categories only found by this detector)
            all_categories = set(f["category"] for f in findings)
            det_categories = set(f["category"] for f in det_findings)

            # Shared categories count
            other_categories = set()
            for other_name, other_f in by_detector.items():
                if other_name != detector_name:
                    other_categories.update(f["category"] for f in other_f)

            unique_to_detector = det_categories - other_categories
            shared = det_categories & other_categories

            # Contribution score: unique findings weighted more heavily
            unique_weight = 0.6
            shared_weight = 0.4

            contribution = (
                (len(unique_to_detector) * unique_weight) +
                (len(shared) * shared_weight)
            )

            # Normalize by total possible
            max_possible = len(all_categories)
            if max_possible > 0:
                contribution = (contribution / max_possible) * 100

            contributions[detector_name] = round(min(contribution, 100), 1)

        return contributions

    def _compute_confidence(self, findings: list, by_detector: dict) -> dict:
        """Compute overall confidence metrics."""
        active_detectors = sum(1 for d in by_detector.values() if d)
        total_detectors = 3

        # Detector agreement: how many findings are cross-validated
        if not findings:
            return {
                "overall_confidence": 1.0,
                "detector_agreement": 1.0,
                "calibration_note": "No findings"
            }

        # Count categories detected by multiple detectors
        by_category_detectors = defaultdict(set)
        for f in findings:
            by_category_detectors[f["category"]].add(f.get("detector", ""))

        cross_validated = sum(
            1 for detectors in by_category_detectors.values()
            if len(detectors) >= 2
        )
        total_categories = len(by_category_detectors)

        agreement = cross_validated / total_categories if total_categories > 0 else 0.0

        # Base confidence on agreement and active detectors
        base_confidence = 0.5 + (agreement * 0.3) + ((active_detectors / total_detectors) * 0.2)

        # Apply calibration multipliers
        if agreement >= 0.5:
            base_confidence *= self.calibration.get("high_agreement_multiplier", 1.2)
        elif active_detectors <= 1:
            base_confidence *= self.calibration.get("single_detector_penalty", 0.85)

        base_confidence = round(min(base_confidence, 1.0), 2)

        # Build calibration note
        parts = []
        if active_detectors >= 2:
            parts.append(f"{active_detectors}/{total_detectors} detectors active")
        if agreement >= 0.5:
            parts.append(f"{cross_validated}/{total_categories} categories cross-validated")
        elif active_detectors <= 1:
            parts.append("single detector - reduced confidence")

        return {
            "overall_confidence": base_confidence,
            "detector_agreement": round(agreement, 2),
            "active_detectors": active_detectors,
            "total_detectors": total_detectors,
            "cross_validated_categories": cross_validated,
            "total_categories": total_categories,
            "calibration_note": "; ".join(parts) if parts else "Default confidence"
        }


def score_text(text: str, findings: list, config: Optional[dict] = None) -> dict:
    """Convenience function to score findings for a text.

    Args:
        text: Original input text (for preview)
        findings: List of finding dicts
        config: Optional config dict

    Returns:
        Complete result dict with risk score, findings, etc.
    """
    scorer = Scorer(config)
    result = scorer.score(findings)
    return {
        "input_preview": text[:100] if text else "",
        **result
    }
