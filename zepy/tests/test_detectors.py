"""
Unit tests for ZEPY Detection Engines and Static Analyzers.
"""

import unittest
import os
from zepy.core.engine import SecurityScanEngine
from zepy.core.models import Severity
from zepy.detectors.ast_detector import AstDetector
from zepy.detectors.regex_detector import RegexDetector


class TestZepyDetectors(unittest.TestCase):
    def setUp(self):
        self.engine = SecurityScanEngine()
        self.samples_dir = os.path.join(os.path.dirname(__file__), "samples")

    def test_ast_unsafe_pickle_detection(self):
        detector = AstDetector()
        code = "import pickle\nobj = pickle.loads(untrusted_data)"
        vulns = detector.scan_code("test.py", code)
        self.assertTrue(any("AST-DESER-001" in v.id for v in vulns))

    def test_ast_torch_missing_weights_only(self):
        detector = AstDetector()
        code = "import torch\nm = torch.load('model.pt')"
        vulns = detector.scan_code("test.py", code)
        self.assertTrue(any("AST-DESER-002" in v.id for v in vulns))

    def test_ast_torch_with_weights_only_safe(self):
        detector = AstDetector()
        code = "import torch\nm = torch.load('model.pt', weights_only=True)"
        vulns = detector.scan_code("test.py", code)
        self.assertFalse(any("AST-DESER-002" in v.id for v in vulns))

    def test_regex_openai_key_detection(self):
        detector = RegexDetector()
        code = 'client = OpenAI(api_key="sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef")'
        vulns = detector.scan_code("test.py", code)
        self.assertTrue(any("SEC-KEY-001" in v.id for v in vulns))

    def test_scan_vulnerable_sample_file(self):
        vuln_file = os.path.join(self.samples_dir, "vulnerable_llm_app.py")
        result = self.engine.scan(vuln_file)
        
        self.assertGreater(len(result.vulnerabilities), 5)
        self.assertGreater(result.metrics.critical_count, 0)
        self.assertGreater(result.metrics.high_count, 0)
        self.assertLess(result.metrics.security_score, 50.0)

    def test_scan_secure_sample_file(self):
        secure_file = os.path.join(self.samples_dir, "secure_llm_app.py")
        result = self.engine.scan(secure_file)
        
        # Ensure no critical or high false positives
        self.assertEqual(result.metrics.critical_count, 0)
        self.assertEqual(result.metrics.high_count, 0)
        self.assertGreaterEqual(result.metrics.security_score, 80.0)


if __name__ == "__main__":
    unittest.main()
