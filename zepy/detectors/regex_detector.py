"""
Zepy - AI Vulnerability Detection Framework
Regex & Pattern Detector: Fast Multi-Pattern Security & Secret Scanner
"""

import re
import math
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory
from zepy.rules.definitions import RULES_DATABASE

_SECRETS_DB_PATH = Path(__file__).parent.parent / "rules" / "secrets_signatures.json"


class RegexDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="Regex & Secret Pattern Detector",
            description="Scans source code for exposed AI API tokens, secrets, insecure HTTP endpoints, and unsafe prompt interpolations."
        )
        self._compiled_patterns = self._init_patterns()

    def _init_patterns(self) -> List[Dict[str, Any]]:
        patterns = []

        # 1. Load signatures from database
        try:
            if _SECRETS_DB_PATH.exists():
                db_data = json.loads(_SECRETS_DB_PATH.read_text(encoding="utf-8"))
                for sig in db_data.get("signatures", []):
                    patterns.append({
                        "rule_id": sig["id"],
                        "regex": re.compile(sig["pattern"]),
                        "desc_extra": f"Exposed {sig['provider']} API key/token",
                        "title": sig.get("title"),
                        "severity": Severity(sig.get("severity", "CRITICAL")),
                        "cwe": sig.get("cwe", "CWE-798"),
                        "owasp": sig.get("owasp", "LLM06:2025-Sensitive-Info-Disclosure"),
                        "remediation": sig.get("remediation", "Store key in environment variables or key vault.")
                    })
        except Exception:
            pass

        # 2. Built-in hardcoded fallback and rule patterns
        builtin = [
            # OpenAI API Keys
            {
                "rule_id": "SEC-KEY-001",
                "regex": re.compile(r'(?:sk-[a-zA-Z0-9_-]{20,T3BlbkFJ[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{48,}|sk-[a-zA-Z0-9]{32,})'),
                "desc_extra": "Exposed OpenAI secret key"
            },
            # Anthropic API Keys
            {
                "rule_id": "SEC-KEY-002",
                "regex": re.compile(r'sk-ant-[a-zA-Z0-9_-]{32,}'),
                "desc_extra": "Exposed Anthropic Claude API key"
            },
            # Hugging Face Access Tokens
            {
                "rule_id": "SEC-KEY-003",
                "regex": re.compile(r'hf_[a-zA-Z0-9]{34,}'),
                "desc_extra": "Exposed HuggingFace user access token"
            },
            # Vector DB Keys (Pinecone, Qdrant, etc.)
            {
                "rule_id": "SEC-KEY-004",
                "regex": re.compile(r'(?:pcsk_[a-zA-Z0-9_-]{32,}|qdrant_api_key\s*=\s*[\'"][a-zA-Z0-9_-]{20,}[\'"])'),
                "desc_extra": "Exposed Vector DB API key"
            },
            # Insecure Plaintext HTTP Model Download
            {
                "rule_id": "SEC-NET-001",
                "regex": re.compile(r'http://(?:huggingface\.co|models\.|download\.|s3\.|storage\.)[^\s\'"]+\.(?:safetensors|pt|pth|bin|onnx|pkl|h5|ckpt)'),
                "desc_extra": "Insecure HTTP endpoint for downloading AI model weights"
            },
            # Direct Prompt Template Interpolation
            {
                "rule_id": "SEC-PROMPT-001",
                "regex": re.compile(r'(?:prompt|system_message|instruction)\s*=\s*f[\'"].*?(?:\{user_input\}|\{query\}|\{input\}|\{request\}|\{prompt\}).*?[\'"]', re.IGNORECASE),
                "desc_extra": "Direct f-string concatenation of user input into prompt template"
            },
            # Sensitive Passwords in System Prompt
            {
                "rule_id": "SEC-PROMPT-002",
                "regex": re.compile(r'(?:system_prompt|system_message)\s*=\s*[\'"].*?(?:password\s*is|api_key\s*is|secret_token\s*=|root_pass).*?[\'"]', re.IGNORECASE),
                "desc_extra": "Sensitive credential or password placed directly in system prompt"
            },
            # Unbounded Token Generation (Missing max_tokens)
            {
                "rule_id": "SEC-DOS-001",
                "regex": re.compile(r'\.(?:create|generate|complete)\s*\((?![^)]*max_tokens)[^)]*model\s*=', re.DOTALL),
                "desc_extra": "LLM completion call missing max_tokens boundary"
            },
            # Scraped data to vector db
            {
                "rule_id": "SEC-POISON-001",
                "regex": re.compile(r'(?:vector_db|vectorstore|collection)\.add_(?:documents|texts)\s*\([^)]*(?:scraped|crawl|unfiltered|raw_web)', re.IGNORECASE),
                "desc_extra": "Direct ingestion of unvalidated web-scraped data into vector database"
            },
        ]
        patterns.extend(builtin)
        return patterns

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy to help distinguish real keys from placeholders."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        for char_code in set(text):
            p = text.count(char_code) / length
            entropy -= p * math.log2(p)
        return entropy

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        lines = code_content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            for pattern_entry in self._compiled_patterns:
                rule_id = pattern_entry["rule_id"]
                regex = pattern_entry["regex"]
                
                for match in regex.finditer(line):
                    matched_str = match.group(0)
                    
                    # Entropy filter for secrets to avoid dummy string alerts
                    if rule_id.startswith("SEC-KEY-") and len(matched_str) > 10:
                        entropy = self._calculate_entropy(matched_str)
                        if entropy < 2.2 and "sk-" not in matched_str and "hf_" not in matched_str:
                            continue

                    snippet = self.extract_snippet(code_content, line_idx)
                    col_idx = match.start() + 1

                    # Look up from rule DB or use signature details
                    rule_def = RULES_DATABASE.get(rule_id)
                    title = pattern_entry.get("title") or (rule_def.title if rule_def else f"Exposed AI Secret ({rule_id})")
                    category = rule_def.category if rule_def else VulnerabilityCategory.API_KEY_LEAK
                    severity = pattern_entry.get("severity") or (rule_def.severity if rule_def else Severity.CRITICAL)
                    cwe = pattern_entry.get("cwe") or (rule_def.cwe_id if rule_def else "CWE-798")
                    owasp = pattern_entry.get("owasp") or (rule_def.owasp_id if rule_def else "LLM06:2025-Sensitive-Info-Disclosure")
                    remediation = pattern_entry.get("remediation") or (rule_def.remediation if rule_def else "Remove hardcoded secret.")
                    desc = rule_def.description if rule_def else pattern_entry.get("desc_extra", "Exposed AI secret token.")

                    vuln = Vulnerability(
                        id=f"{rule_id}-{line_idx}-{col_idx}",
                        title=title,
                        category=category,
                        severity=severity,
                        description=f"{desc} (Matched: {matched_str[:8]}...{matched_str[-4:] if len(matched_str) > 12 else ''})",
                        file_path=file_path,
                        line_number=line_idx,
                        column_number=col_idx,
                        code_snippet=snippet,
                        remediation=remediation,
                        cwe_id=cwe,
                        owasp_id=owasp,
                        confidence=0.92,
                        metadata={"detector": "regex_detector", "rule_id": rule_id, "match": matched_str[:20]}
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities
