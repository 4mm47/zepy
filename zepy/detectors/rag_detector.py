"""
Zepy - AI Vulnerability Detection Framework
RAG Detector: Static analyzer for Retrieval-Augmented Generation & Vector DB Pipelines.
"""

import json
import re
from pathlib import Path
from typing import List, Optional
from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory

_RAG_SIGNATURES_FILE = Path(__file__).parent.parent / "rules" / "rag_security_signatures.json"


def _load_rag_signatures() -> list:
    try:
        return json.loads(_RAG_SIGNATURES_FILE.read_text(encoding="utf-8")).get("signatures", [])
    except Exception:
        return []


_RAG_SIGNATURES = _load_rag_signatures()


class RagDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="RAG & Vector Pipeline Detector",
            description="Detects unvalidated context injection, Vector DB filter injection, and unsafe document loaders in RAG workflows."
        )
        self.compiled_rules = []
        for r in _RAG_SIGNATURES:
            try:
                self.compiled_rules.append({
                    "id": r["id"],
                    "title": r["title"],
                    "re": re.compile(r["pattern"], re.IGNORECASE | re.DOTALL),
                    "severity": Severity(r["severity"].upper()),
                    "cwe": r["cwe"],
                    "owasp": r["owasp"],
                    "remediation": r["remediation"],
                })
            except Exception:
                pass

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []

        # 1. Signature-based checks
        for rule in self.compiled_rules:
            for match in rule["re"].finditer(code_content):
                line_no = code_content[: match.start()].count("\n") + 1
                col_no = match.start() - code_content.rfind("\n", 0, match.start())
                snippet = self.extract_snippet(code_content, line_no)

                vuln = Vulnerability(
                    id=f"{rule['id']}-{line_no}",
                    title=rule["title"],
                    category=VulnerabilityCategory.UNVALIDATED_RAG,
                    severity=rule["severity"],
                    description=f"RAG Security risk detected: {rule['title']} (Matched: {match.group(0)[:80]})",
                    file_path=file_path,
                    line_number=line_no,
                    column_number=col_no,
                    code_snippet=snippet,
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe"],
                    owasp_id=rule["owasp"],
                    confidence=0.92,
                    metadata={"detector": "rag_detector", "rule_id": rule["id"]}
                )
                findings.append(vuln)

        # 2. Heuristic check: LangChain / LlamaIndex unverified web retrieval
        if any(rag_lib in code_content for rag_lib in ["langchain", "llama_index", "chromadb", "pinecone"]):
            if "RecursiveUrlLoader" in code_content or "UnstructuredURLLoader" in code_content:
                if "verify_ssl=False" in code_content or "ssl_verify=False" in code_content:
                    line_no = 1
                    for idx, l in enumerate(code_content.splitlines(), 1):
                        if "verify_ssl=False" in l or "ssl_verify=False" in l:
                            line_no = idx
                            break
                    snippet = self.extract_snippet(code_content, line_no)
                    vuln = Vulnerability(
                        id=f"RAG-SSL-001-{line_no}",
                        title="Unverified SSL in Web RAG Document Loader",
                        category=VulnerabilityCategory.INSECURE_COMMUNICATION,
                        severity=Severity.HIGH,
                        description="RAG document ingestion loader disables SSL certificate verification, exposing vector index to MITM poisoning.",
                        file_path=file_path,
                        line_number=line_no,
                        column_number=1,
                        code_snippet=snippet,
                        remediation="Enforce TLS certificate validation on all document crawling endpoints.",
                        cwe_id="CWE-295",
                        owasp_id="LLM03:2025-Training-Poisoning",
                        confidence=0.95,
                        metadata={"detector": "rag_detector", "rule_id": "RAG-SSL-001"}
                    )
                    findings.append(vuln)

        return findings
