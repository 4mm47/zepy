"""
Zepy - AI Vulnerability Detection Framework
"""

__version__ = "1.0.0"
__author__ = "ZEPY Security Research"

from zepy.core.models import (
    Severity,
    VulnerabilityCategory,
    Vulnerability,
    ScanResult,
    ScanMetrics,
    PromptThreatDetection,
)
from zepy.core.engine import SecurityScanEngine
from zepy.core.reporter import SecurityReporter
from zepy.detectors.prompt_analyzer import PromptAnalyzer

__all__ = [
    "Severity",
    "VulnerabilityCategory",
    "Vulnerability",
    "ScanResult",
    "ScanMetrics",
    "PromptThreatDetection",
    "SecurityScanEngine",
    "SecurityReporter",
    "PromptAnalyzer",
]
