"""
Zepy - AI Vulnerability Detection Framework
Detectors module package.
"""

from zepy.detectors.base import BaseDetector
from zepy.detectors.ast_detector import AstDetector
from zepy.detectors.regex_detector import RegexDetector
from zepy.detectors.llm_owasp_detector import LLMOwaspDetector
from zepy.detectors.prompt_analyzer import PromptAnalyzer

__all__ = [
    "BaseDetector",
    "AstDetector",
    "RegexDetector",
    "LLMOwaspDetector",
    "PromptAnalyzer",
]
