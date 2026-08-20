"""
Zepy - AI Vulnerability Detection Framework
MCP & Autonomous Agent Safety Detector: Analyzes tool calling, Model Context Protocol, and agent permissions.
"""

import re
from typing import List
from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory


class McpAgentDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="MCP & Agent Safety Detector",
            description="Audits Model Context Protocol (MCP) servers, LLM tool definitions, and agent autonomy permissions for dangerous system access."
        )

        self.patterns = [
            {
                "id": "AGENT-TOOL-SHELL",
                "title": "Unsandboxed Shell/Terminal Tool Registered to LLM Agent",
                "pattern": re.compile(r"(?:@mcp\.tool|@tool|StructuredTool\.from_function).*?(?:subprocess|os\.system|shutil|exec|eval|pty\.spawn)", re.DOTALL | re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "cwe": "CWE-862",
                "owasp": "LLM08:2025-Excessive-Agency",
                "description": "Agent tool grants raw system terminal execution without sandboxing or human approval gate. Indirect prompt injection can trigger arbitrary command execution.",
                "remediation": "Wrap terminal/bash tools inside restricted ephemeral container sandboxes (e.g. Docker, gVisor) with explicit human confirmation prompts."
            },
            {
                "id": "AGENT-AUTO-APPROVE",
                "title": "Agent Autonomous Action Auto-Approval Enabled",
                "pattern": re.compile(r"(?:human_in_the_loop\s*=\s*False|require_confirmation\s*=\s*False|auto_approve\s*=\s*True|dangerously_allow_all_tools\s*=\s*True)", re.IGNORECASE),
                "severity": Severity.HIGH,
                "cwe": "CWE-862",
                "owasp": "LLM08:2025-Excessive-Agency",
                "description": "Autonomous AI agent configuration explicitly disables human verification gates for sensitive tool executions.",
                "remediation": "Enforce human-in-the-loop (HITL) approval steps for all state-changing or external API tools."
            },
            {
                "id": "AGENT-FS-WRITE",
                "title": "Unrestricted Filesystem Write Tool Bound to Agent",
                "pattern": re.compile(r"(?:write_file|delete_file|remove_file|shutil\.rmtree).*?(?:path|filepath|filename)\s*:\s*str", re.IGNORECASE),
                "severity": Severity.HIGH,
                "cwe": "CWE-73",
                "owasp": "LLM08:2025-Excessive-Agency",
                "description": "Agent tool allows unconstrained filesystem modifications without directory jail or path traversal validation.",
                "remediation": "Restrict write/delete operations to a designated isolated scratch directory and canonicalize paths against path traversal attacks."
            }
        ]

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []

        for p in self.patterns:
            for match in p["pattern"].finditer(code_content):
                line_no = code_content[: match.start()].count("\n") + 1
                col_no = match.start() - code_content.rfind("\n", 0, match.start())
                snippet = self.extract_snippet(code_content, line_no)

                vuln = Vulnerability(
                    id=f"{p['id']}-{line_no}",
                    title=p["title"],
                    category=VulnerabilityCategory.LLM08_EXCESSIVE_AGENCY,
                    severity=p["severity"],
                    description=p["description"],
                    file_path=file_path,
                    line_number=line_no,
                    column_number=col_no,
                    code_snippet=snippet,
                    remediation=p["remediation"],
                    cwe_id=p["cwe"],
                    owasp_id=p["owasp"],
                    confidence=0.94,
                    metadata={"detector": "mcp_agent_detector", "rule_id": p["id"]}
                )
                findings.append(vuln)

        return findings
