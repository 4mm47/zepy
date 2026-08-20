"""
Zepy - Advanced Security Detectors & Integrations Test Suite
"""

import unittest
import os
import json
import tempfile
from pathlib import Path

from zepy.detectors.supply_chain_detector import SupplyChainDetector
from zepy.detectors.rag_detector import RagDetector
from zepy.detectors.mcp_agent_detector import McpAgentDetector
from zepy.detectors.model_artifact_detector import ModelArtifactDetector
from zepy.rules.yaml_rule_loader import YamlRuleDetector, load_custom_rules
from zepy.core.diff_engine import DiffEngine, DiffReport
from zepy.core.models import ScanResult, Vulnerability, Severity, VulnerabilityCategory
from zepy.integrations.ci_generator import (
    generate_github_actions_yaml,
    generate_gitlab_ci_yaml,
    generate_pre_commit_config,
    write_ci_file,
)
from zepy.integrations.sbom import generate_sbom, export_sbom
from zepy.integrations.compliance import generate_compliance_html, export_compliance_report
from zepy.integrations.audit_log import log_scan, log_prompt_analysis, read_audit_log
from zepy.core.reporter import SecurityReporter


class TestSupplyChainDetector(unittest.TestCase):
    def test_detect_vulnerable_packages(self):
        detector = SupplyChainDetector()
        reqs_content = (
            "langchain==0.1.0\n"
            "transformers==4.30.0\n"
            "torch==2.0.1\n"
            "safe-package>=1.0.0\n"
        )
        findings = detector.scan_code("requirements.txt", reqs_content)
        self.assertTrue(len(findings) >= 2)
        cves = [f.metadata.get("cve") for f in findings]
        self.assertTrue(any("CVE" in c for c in cves if c))

    def test_clean_packages(self):
        detector = SupplyChainDetector()
        reqs_content = (
            "langchain>=0.2.0\n"
            "transformers>=4.40.0\n"
            "torch>=2.3.0\n"
        )
        findings = detector.scan_code("requirements.txt", reqs_content)
        self.assertEqual(len(findings), 0)


class TestRagAndAgentDetectors(unittest.TestCase):
    def test_rag_context_injection_detection(self):
        detector = RagDetector()
        code = "messages = [{'role': 'system', 'content': f'Here is user context: {retrieved_docs}'}]"
        findings = detector.scan_code("rag_pipeline.py", code)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].category, VulnerabilityCategory.UNVALIDATED_RAG)

    def test_mcp_agent_shell_tool_detection(self):
        detector = McpAgentDetector()
        code = "@mcp.tool()\ndef run_terminal_command(cmd: str):\n    subprocess.run(cmd, shell=True)\n"
        findings = detector.scan_code("mcp_server.py", code)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_model_artifact_pickle_weights(self):
        detector = ModelArtifactDetector()
        findings = detector.scan_code("pytorch_model.bin", "")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].category, VulnerabilityCategory.LLM05_SUPPLY_CHAIN)


class TestDiffEngine(unittest.TestCase):
    def test_diff_detection(self):
        v1 = Vulnerability(
            id="AST-DESER-001-10",
            title="Unsafe Pickle",
            category=VulnerabilityCategory.DESERIALIZATION,
            severity=Severity.CRITICAL,
            description="Pickle RCE",
            file_path="app.py",
            line_number=10
        )
        v2 = Vulnerability(
            id="SEC-KEY-001-20",
            title="OpenAI Key",
            category=VulnerabilityCategory.API_KEY_LEAK,
            severity=Severity.HIGH,
            description="Exposed Key",
            file_path="config.py",
            line_number=20
        )
        v3 = Vulnerability(
            id="AST-EXEC-001-30",
            title="Eval Usage",
            category=VulnerabilityCategory.CODE_INJECTION,
            severity=Severity.HIGH,
            description="Eval used",
            file_path="eval.py",
            line_number=30
        )

        baseline = ScanResult(target_path=".")
        baseline.vulnerabilities = [v1, v2]

        current = ScanResult(target_path=".")
        current.vulnerabilities = [v2, v3]  # v1 fixed, v3 new (regression)

        diff = DiffEngine.compute_diff(baseline, current)
        self.assertEqual(len(diff.new_findings), 1)
        self.assertEqual(diff.new_findings[0].id, v3.id)
        self.assertEqual(len(diff.fixed_findings), 1)
        self.assertEqual(diff.fixed_findings[0].id, v1.id)
        self.assertEqual(len(diff.persisting_findings), 1)


class TestCIGenerators(unittest.TestCase):
    def test_github_actions_generator(self):
        yaml_content = generate_github_actions_yaml(fail_on="CRITICAL")
        self.assertIn("ZEPY AI", yaml_content)
        self.assertIn("github/codeql-action/upload-sarif", yaml_content)
        self.assertIn("--fail-on CRITICAL", yaml_content)

    def test_gitlab_ci_generator(self):
        yaml_content = generate_gitlab_ci_yaml(fail_on="HIGH")
        self.assertIn("zepy-ai-security-scan", yaml_content)
        self.assertIn("--fail-on HIGH", yaml_content)

    def test_pre_commit_generator(self):
        yaml_content = generate_pre_commit_config()
        self.assertIn("zepy-scan", yaml_content)


class TestSBOMAndCompliance(unittest.TestCase):
    def test_sbom_generation(self):
        result = ScanResult(target_path=".")
        bom = generate_sbom(scan_result=result, project_name="TestApp")
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertIn("components", bom)

    def test_compliance_soc2(self):
        result = ScanResult(target_path=".")
        result.vulnerabilities = [
            Vulnerability(
                id="SEC-KEY-001-14",
                title="OpenAI Key",
                category=VulnerabilityCategory.API_KEY_LEAK,
                severity=Severity.HIGH,
                description="Hardcoded key",
                file_path="keys.py",
                line_number=14,
                cwe_id="CWE-798",
                owasp_id="LLM06"
            )
        ]
        result.compute_metrics(duration=0.1, files_count=1, lines_count=20)
        html = generate_compliance_html(result, framework="soc2", org_name="TestOrg")
        self.assertIn("SOC 2 Type II", html)
        self.assertIn("CC6", html)
        self.assertIn("TestOrg", html)


class TestSARIFExport(unittest.TestCase):
    def test_sarif_file_export(self):
        result = ScanResult(target_path=".")
        result.vulnerabilities = [
            Vulnerability(
                id="AST-DESER-002-37",
                title="torch.load missing weights_only",
                category=VulnerabilityCategory.DESERIALIZATION,
                severity=Severity.CRITICAL,
                description="torch.load RCE",
                file_path="loader.py",
                line_number=37,
                cwe_id="CWE-502",
                owasp_id="LLM05"
            )
        ]
        result.compute_metrics(duration=0.1, files_count=1, lines_count=50)

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            sarif_path = f.name

        try:
            SecurityReporter.export_sarif(result, sarif_path)
            self.assertTrue(os.path.exists(sarif_path))
            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif_json = json.load(f)
            self.assertEqual(sarif_json["version"], "2.1.0")
            self.assertEqual(len(sarif_json["runs"][0]["results"]), 1)
            self.assertEqual(sarif_json["runs"][0]["results"][0]["ruleId"], "AST-DESER-002")
        finally:
            if os.path.exists(sarif_path):
                os.remove(sarif_path)


if __name__ == "__main__":
    unittest.main()
