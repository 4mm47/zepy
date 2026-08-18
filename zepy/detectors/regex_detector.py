"""
Zepy - AI Vulnerability Detection Framework
Regex & Pattern Detector: Fast Multi-Pattern Security & Secret Scanner
"""

import re
import math
from typing import List, Dict, Any, Tuple
from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory
from zepy.rules.definitions import RULES_DATABASE


class RegexDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="Regex & Secret Pattern Detector",
            description="Scans source code for exposed AI API tokens, secrets, insecure HTTP endpoints, and unsafe prompt interpolations."
        )
        self._compiled_patterns = self._init_patterns()

    def _init_patterns(self) -> List[Dict[str, Any]]:
        patterns = [
            # 1. OpenAI API Keys
            {
                "rule_id": "SEC-KEY-001",
                "regex": re.compile(r'(?:sk-[a-zA-Z0-9_-]{20,T3BlbkFJ[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{48,}|sk-[a-zA-Z0-9]{32,})'),
                "desc_extra": "Exposed OpenAI secret key"
            },
            # 2. Anthropic API Keys
            {
                "rule_id": "SEC-KEY-002",
                "regex": re.compile(r'sk-ant-[a-zA-Z0-9_-]{32,}'),
                "desc_extra": "Exposed Anthropic Claude API key"
            },
            # 3. Hugging Face Access Tokens
            {
                "rule_id": "SEC-KEY-003",
                "regex": re.compile(r'hf_[a-zA-Z0-9]{34,}'),
                "desc_extra": "Exposed HuggingFace user access token"
            },
            # 4. Vector DB Keys (Pinecone, Qdrant, etc.)
            {
                "rule_id": "SEC-KEY-004",
                "regex": re.compile(r'(?:pcsk_[a-zA-Z0-9_-]{32,}|qdrant_api_key\s*=\s*[\'"][a-zA-Z0-9_-]{20,}[\'"])'),
                "desc_extra": "Exposed Vector DB API key"
            },
            # 5. Insecure Plaintext HTTP Model Download
            {
                "rule_id": "SEC-NET-001",
                "regex": re.compile(r'http://(?:huggingface\.co|models\.|download\.|s3\.|storage\.)[^\s\'"]+\.(?:safetensors|pt|pth|bin|onnx|pkl|h5|ckpt)'),
                "desc_extra": "Insecure HTTP endpoint for downloading AI model weights"
            },
            # 6. Direct Prompt Template Interpolation
            {
                "rule_id": "SEC-PROMPT-001",
                "regex": re.compile(r'(?:prompt|system_message|instruction)\s*=\s*f[\'"].*?(?:\{user_input\}|\{query\}|\{input\}|\{request\}|\{prompt\}).*?[\'"]', re.IGNORECASE),
                "desc_extra": "Direct f-string concatenation of user input into prompt template"
            },
            # 7. Sensitive Passwords in System Prompt
            {
                "rule_id": "SEC-PROMPT-002",
                "regex": re.compile(r'(?:system_prompt|system_message)\s*=\s*[\'"].*?(?:password\s*is|api_key\s*is|secret_token\s*=|root_pass).*?[\'"]', re.IGNORECASE),
                "desc_extra": "Sensitive credential or password placed directly in system prompt"
            },
            # 8. Unbounded Token Generation (Missing max_tokens)
            {
                "rule_id": "SEC-DOS-001",
                "regex": re.compile(r'\.(?:create|generate|complete)\s*\((?![^)]*max_tokens)[^)]*model\s*=', re.DOTALL),
                "desc_extra": "LLM completion call missing max_tokens boundary"
            },
            # 9. Scraped data to vector db
            {
                "rule_id": "SEC-POISON-001",
                "regex": re.compile(r'(?:vector_db|vectorstore|collection)\.add_(?:documents|texts)\s*\([^)]*(?:scraped|crawl|unfiltered|raw_web)', re.IGNORECASE),
                "desc_extra": "Direct ingestion of unvalidated web-scraped data into vector database"
            },
        ]
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
            # Skip comments if checking non-prompt issues
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                # Check for secrets even in comments
                is_comment = True
            else:
                is_comment = False

            for pattern_entry in self._compiled_patterns:
                rule_id = pattern_entry["rule_id"]
                rule = RULES_DATABASE.get(rule_id)
                if not rule:
                    continue

                matches = pattern_entry["regex"].finditer(line)
                for match in matches:
                    matched_text = match.group(0)

                    # For secret keys, filter out dummy strings like "sk-xxxx", "sk-1234"
                    if "KEY" in rule_id and len(set(matched_text)) < 8:
                        continue

                    # Mask sensitive key in reports
                    if "KEY" in rule_id and len(matched_text) > 10:
                        masked = matched_text[:6] + "..." + matched_text[-4:]
                    else:
                        masked = matched_text

                    snippet = self.extract_snippet(code_content, line_idx)
                    vuln = Vulnerability(
                        id=f"{rule.id}-{line_idx}-{match.start()}",
                        title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        description=f"{rule.description} (Matched: {masked})",
                        file_path=file_path,
                        line_number=line_idx,
                        column_number=match.start() + 1,
                        code_snippet=snippet,
                        remediation=rule.remediation,
                        cwe_id=rule.cwe_id,
                        owasp_id=rule.owasp_id,
                        confidence=0.92,
                        metadata={"detector": "regex_detector", "rule_id": rule.id, "match": masked}
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities
