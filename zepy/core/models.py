"""
Zepy - AI Vulnerability Detection Framework
Core data models for findings, severity levels, categories, and scan results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        colors = {
            Severity.CRITICAL: "#FF2A6D",  # Neon Crimson
            Severity.HIGH: "#FF5E00",      # Neon Orange
            Severity.MEDIUM: "#FFB800",    # Amber Yellow
            Severity.LOW: "#05D9E8",       # Cyber Cyan
            Severity.INFO: "#01FFC3",      # Neon Mint Green
        }
        return colors.get(self, "#FFFFFF")

    @property
    def rich_color(self) -> str:
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "bold dark_orange",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "bold green",
        }
        return colors.get(self, "white")

    @property
    def weight(self) -> int:
        weights = {
            Severity.CRITICAL: 50,
            Severity.HIGH: 30,
            Severity.MEDIUM: 15,
            Severity.LOW: 5,
            Severity.INFO: 1,
        }
        return weights.get(self, 0)


class VulnerabilityCategory(str, Enum):
    # OWASP Top 10 for LLM
    LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection & Jailbreak"
    LLM02_INSECURE_OUTPUT = "LLM02: Insecure Output Handling"
    LLM03_TRAINING_POISONING = "LLM03: Training/Fine-Tuning Data Poisoning"
    LLM04_MODEL_DENIAL_OF_SERVICE = "LLM04: Model Denial of Service & Resource Exhaustion"
    LLM05_SUPPLY_CHAIN = "LLM05: Supply Chain & Insecure Checkpoints"
    LLM06_SENSITIVE_INFO = "LLM06: Sensitive Information Disclosure"
    LLM07_INSECURE_PLUGIN = "LLM07: Insecure Plugin / Excessive Agency"
    LLM08_EXCESSIVE_AGENCY = "LLM08: Excessive Agency & Unsafe Autonomy"
    LLM09_OVERRELIANCE = "LLM09: Overreliance & Lack of Guardrails"
    LLM10_MODEL_THEFT = "LLM10: Model Theft & System Prompt Extraction"
    
    # AI System & Traditional Security
    DESERIALIZATION = "AI Deserialization & Unsafe Model Loading"
    API_KEY_LEAK = "Hardcoded AI Secrets & Credentials"
    UNVALIDATED_RAG = "Unvalidated RAG & Vector Injection"
    CODE_INJECTION = "Dynamic Code Execution (eval/exec/subprocess)"
    INSECURE_COMMUNICATION = "Insecure Model Endpoint & Network Protocol"
    DATA_EXFILTRATION = "AI Data Exfiltration Risk"


@dataclass
class Vulnerability:
    id: str
    title: str
    category: VulnerabilityCategory
    severity: Severity
    description: str
    file_path: str
    line_number: int
    column_number: int = 1
    code_snippet: str = ""
    remediation: str = ""
    cwe_id: str = ""
    owasp_id: str = ""
    confidence: float = 0.95
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value if isinstance(self.category, VulnerabilityCategory) else str(self.category),
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class PromptThreatDetection:
    is_threat: bool
    threat_score: float  # 0.0 to 100.0
    threat_level: Severity
    threat_types: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    sanitized_prompt: str = ""
    remediation_advice: str = ""
    entropy_score: float = 0.0
    obfuscation_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_threat": self.is_threat,
            "threat_score": round(self.threat_score, 2),
            "threat_level": self.threat_level.value,
            "threat_types": self.threat_types,
            "matched_patterns": self.matched_patterns,
            "sanitized_prompt": self.sanitized_prompt,
            "remediation_advice": self.remediation_advice,
            "entropy_score": round(self.entropy_score, 2),
            "obfuscation_detected": self.obfuscation_detected,
        }


@dataclass
class ScanMetrics:
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    scan_duration_seconds: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    security_score: float = 100.0  # 0 to 100

    def calculate_security_score(self) -> float:
        penalty = (
            self.critical_count * 25 +
            self.high_count * 15 +
            self.medium_count * 5 +
            self.low_count * 1.5 +
            self.info_count * 0.2
        )
        score = max(0.0, 100.0 - penalty)
        self.security_score = round(score, 1)
        return self.security_score


@dataclass
class ScanResult:
    target_path: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    metrics: ScanMetrics = field(default_factory=ScanMetrics)
    scanner_version: str = "1.0.0"

    def compute_metrics(self, duration: float, files_count: int, lines_count: int):
        self.metrics.total_files_scanned = files_count
        self.metrics.total_lines_scanned = lines_count
        self.metrics.scan_duration_seconds = round(duration, 3)
        self.metrics.critical_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
        self.metrics.high_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
        self.metrics.medium_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)
        self.metrics.low_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)
        self.metrics.info_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.INFO)
        self.metrics.calculate_security_score()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "scanner_version": self.scanner_version,
            "metrics": {
                "total_files_scanned": self.metrics.total_files_scanned,
                "total_lines_scanned": self.metrics.total_lines_scanned,
                "scan_duration_seconds": self.metrics.scan_duration_seconds,
                "critical_count": self.metrics.critical_count,
                "high_count": self.metrics.high_count,
                "medium_count": self.metrics.medium_count,
                "low_count": self.metrics.low_count,
                "info_count": self.metrics.info_count,
                "security_score": self.metrics.security_score,
            },
            "findings_count": len(self.vulnerabilities),
            "findings": [v.to_dict() for v in self.vulnerabilities],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
