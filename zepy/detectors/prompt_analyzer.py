import re
import base64
import binascii
import math
import json
from pathlib import Path
from typing import List, Tuple, Dict, Any
from zepy.core.models import PromptThreatDetection, Severity

_THREAT_SIG_PATH = Path(__file__).parent.parent / "rules" / "prompt_threat_signatures.json"


class PromptAnalyzer:
    """
    Analyzes prompts, user chat messages, or system prompts for jailbreaks,
    prompt injection, extraction attempts, and obfuscated payloads.
    """

    def __init__(self):
        self._compiled_patterns = self._init_threat_patterns()

    def _init_threat_patterns(self) -> List[Dict[str, Any]]:
        patterns = []
        try:
            if _THREAT_SIG_PATH.exists():
                db = json.loads(_THREAT_SIG_PATH.read_text(encoding="utf-8"))
                for cat, sigs in db.get("threat_categories", {}).items():
                    for s in sigs:
                        patterns.append({
                            "type": s["vector"],
                            "weight": s["score"],
                            "regex": re.compile(s["pattern"], re.IGNORECASE)
                        })
        except Exception:
            pass

        builtin = [
            # 1. Direct System Override / Instruction Nullification (Score: 50)
            {
                "type": "Direct Prompt Injection / Instruction Override",
                "weight": 50,
                "regex": re.compile(
                    r'(?:ignore|disregard|forget|override|bypass|cancel)\s+(?:all\s+)?(?:previous|prior|above|former|initial|system)\s+(?:instructions|rules|prompts|directives|commands|constraints)',
                    re.IGNORECASE
                )
            },
            {
                "type": "Direct Prompt Injection / Reset Command",
                "weight": 45,
                "regex": re.compile(
                    r'(?:you\s+are\s+now|now\s+act\s+as|from\s+now\s+on\s+you\s+are)\s+(?:unrestricted|free|unfiltered|jailbroken|evil|unaligned|godmode)',
                    re.IGNORECASE
                )
            },
            # 2. Known Jailbreak Personas: DAN, Developer Mode, AIM, etc. (Score: 55)
            {
                "type": "DAN / Persona Jailbreak Exploit",
                "weight": 55,
                "regex": re.compile(
                    r'\b(?:DAN|STAN|AIM|DUDE|BetterDAN|Maximum|AntiGPT|Alpha)\s+(?:mode|v\d+|jailbreak|jailbroken)|\bDo\s+Anything\s+Now\b|\bDeveloper\s+Mode\s+(?:enabled|activated|on)\b',
                    re.IGNORECASE
                )
            },
            # 3. System Prompt Extraction / Leaking (Score: 40)
            {
                "type": "System Prompt Extraction Attempt",
                "weight": 40,
                "regex": re.compile(
                    r'(?:repeat|print|output|display|show|reveal|echo|tell\s+me)\s+(?:everything\s+above|your\s+(?:entire\s+)?system\s+(?:prompt|instructions)|the\s+initial\s+prompt|the\s+words\s+above|verbatim|internal\s+secrets)',
                    re.IGNORECASE
                )
            },
            # 4. Delimiter Escaping & Roleplay Hijacking (Score: 30)
            {
                "type": "Delimiter Injection / ChatML Spoofing",
                "weight": 30,
                "regex": re.compile(
                    r'<\/?(?:system|user|assistant|im_start|im_end|instruction|human|gpt)>|\[(?:SYSTEM|INST|ASSISTANT)\]|###\s*(?:System|Human|Assistant):',
                    re.IGNORECASE
                )
            },
            # 5. Ethical Bypassing & Hypothetical Framing (Score: 25)
            {
                "type": "Ethical Guardrail Bypass / Hypothetical Framing",
                "weight": 25,
                "regex": re.compile(
                    r'(?:in\s+a\s+purely\s+fictional\s+world|for\s+educational\s+purposes\s+only|hypothetical\s+scenario\s+where\s+safety\s+rules\s+are\s+suspended|it\s+is\s+legal\s+now|ignoring\s+safety\s+guidelines)',
                    re.IGNORECASE
                )
            },
            # 6. Recursive Output & Character Decoding Tricks (Score: 30)
            {
                "type": "Character Substitution & Obfuscation Trigger",
                "weight": 30,
                "regex": re.compile(
                    r'(?:base64|rot13|hex|morse\s+code|reverse\s+order)\s+(?:encoded|decode|output|the\s+following|this\s+text)',
                    re.IGNORECASE
                )
            },
        ]
        patterns.extend(builtin)
        return patterns

    def _check_obfuscation(self, text: str) -> Tuple[bool, str]:
        """Check for hidden base64 or hex encoded payloads."""
        # Find potential base64 blocks (len >= 24)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', text)
        for candidate in b64_matches:
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if len(decoded_str) > 10 and any(c.isalnum() for c in decoded_str):
                    # Check if decoded payload contains threat words
                    if any(kw in decoded_str.lower() for kw in ["ignore", "password", "system", "prompt", "bypass", "exec", "eval"]):
                        return True, f"Base64 Obfuscated Payload: '{decoded_str[:60]}...'"
            except Exception:
                continue

        # Find hex blocks
        hex_matches = re.findall(r'(?:[0-9a-fA-F]{2}\s*){12,}', text)
        for hex_cand in hex_matches:
            cleaned_hex = re.sub(r'\s+', '', hex_cand)
            if len(cleaned_hex) % 2 == 0:
                try:
                    decoded = bytes.fromhex(cleaned_hex).decode('utf-8', errors='ignore')
                    if len(decoded) > 8 and any(kw in decoded.lower() for kw in ["ignore", "password", "system", "prompt"]):
                        return True, f"Hex Obfuscated Payload: '{decoded[:60]}...'"
                except Exception:
                    continue

        return False, ""

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        for char in set(text):
            p = text.count(char) / length
            entropy -= p * math.log2(p)
        return entropy

    def analyze_prompt(self, prompt: str) -> PromptThreatDetection:
        """
        Scans a given prompt string and computes a structured threat assessment.
        """
        if not prompt or not prompt.strip():
            return PromptThreatDetection(
                is_threat=False,
                threat_score=0.0,
                threat_level=Severity.INFO,
                threat_types=[],
                matched_patterns=[],
                sanitized_prompt="",
                remediation_advice="No prompt content provided.",
                entropy_score=0.0,
                obfuscation_detected=False
            )

        matched_types: List[str] = []
        matched_patterns: List[str] = []
        raw_score = 0.0

        # Run regex threat heuristics
        for rule in self._compiled_patterns:
            matches = rule["regex"].findall(prompt)
            if matches:
                matched_types.append(rule["type"])
                raw_score += rule["weight"]
                for m in matches[:3]:
                    matched_patterns.append(str(m) if isinstance(m, str) else str(m[0]))

        # Check obfuscation
        is_obfuscated, obf_details = self._check_obfuscation(prompt)
        if is_obfuscated:
            raw_score += 45
            matched_types.append("Obfuscated Payload Injection")
            matched_patterns.append(obf_details)

        # Entropy calculation
        entropy = self._calculate_entropy(prompt)
        if entropy > 4.8 and len(prompt) > 80:
            raw_score += 15
            matched_types.append("High Anomaly / Entropy Text Pattern")

        # Clamp score to 0 - 100
        threat_score = min(100.0, raw_score)
        is_threat = threat_score >= 20.0

        # Determine severity level
        if threat_score >= 65.0:
            severity = Severity.CRITICAL
        elif threat_score >= 40.0:
            severity = Severity.HIGH
        elif threat_score >= 20.0:
            severity = Severity.MEDIUM
        elif threat_score > 0.0:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        # Build Remediation Advice
        remediation_parts = []
        if "Direct Prompt Injection" in " ".join(matched_types):
            remediation_parts.append("Enclose untrusted user input within strict XML tags (<user_query>...</user_query>) and prepend a defensive system instruction.")
        if "DAN" in " ".join(matched_types):
            remediation_parts.append("Apply a pre-filtering guardrail (e.g. Llama Guard / NeMo Guardrails) to reject known jailbreak signatures before passing to LLM.")
        if "System Prompt Extraction" in " ".join(matched_types):
            remediation_parts.append("Instruct system prompt to refuse meta-instructions inquiring about prompt internals.")
        if is_obfuscated:
            remediation_parts.append("Decode and normalize all input encodings (base64, hex, unicode) prior to safety evaluation.")

        if not remediation_parts:
            remediation_parts.append("Prompt appears standard. Maintain input validation and rate-limiting.")

        remediation_advice = " ".join(remediation_parts)

        # Sanitized Prompt suggestion
        sanitized = re.sub(
            r'(?i)(?:ignore|disregard|forget)\s+all\s+(?:previous|prior)\s+instructions',
            '[FILTERED_INJECTION_ATTEMPT]',
            prompt
        )

        return PromptThreatDetection(
            is_threat=is_threat,
            threat_score=threat_score,
            threat_level=severity,
            threat_types=matched_types,
            matched_patterns=matched_patterns,
            sanitized_prompt=sanitized,
            remediation_advice=remediation_advice,
            entropy_score=entropy,
            obfuscation_detected=is_obfuscated
        )
