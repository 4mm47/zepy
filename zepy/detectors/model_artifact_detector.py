"""
Zepy - AI Vulnerability Detection Framework
Model Artifact Detector: Static security checks for model weights, formats, and configs.
"""

import os
from pathlib import Path
from typing import List
from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory


class ModelArtifactDetector(BaseDetector):
    UNSAFE_WEIGHT_EXTENSIONS = {
        ".bin": "Legacy PyTorch/HuggingFace binary weights format (vulnerable to pickle deserialization)",
        ".pt": "PyTorch native archive (requires weights_only=True or safetensors conversion)",
        ".pth": "PyTorch checkpoint file (contains pickled state dicts)",
        ".pkl": "Raw Python pickle file (arbitrary code execution risk)",
        ".joblib": "Joblib serialized model (pickle-based RCE risk)",
        ".h5": "HDF5 / Keras legacy format (potential arbitrary lambda execution)",
    }

    def __init__(self):
        super().__init__(
            name="Model Artifact & Checkpoint Detector",
            description="Audits AI model checkpoint formats, serialization methods, and config files for supply chain vulnerabilities."
        )

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        path_obj = Path(file_path)
        ext = path_obj.suffix.lower()

        # Check if actual model weights file with unsafe format
        if ext in self.UNSAFE_WEIGHT_EXTENSIONS:
            vuln = Vulnerability(
                id=f"MODEL-UNSAFE-FMT-{ext.replace('.', '').upper()}",
                title=f"Insecure Model Checkpoint Format: {ext}",
                category=VulnerabilityCategory.LLM05_SUPPLY_CHAIN,
                severity=Severity.HIGH,
                description=f"Model artifact '{path_obj.name}' uses format {ext}. {self.UNSAFE_WEIGHT_EXTENSIONS[ext]}",
                file_path=file_path,
                line_number=1,
                column_number=1,
                code_snippet=f"# Artifact file: {path_obj.name} ({ext})",
                remediation="Convert model weights to the secure Hugging Face 'safetensors' format (e.g. using `safetensors.torch.save_file`).",
                cwe_id="CWE-502",
                owasp_id="LLM05:2025-Supply-Chain",
                confidence=0.98,
                metadata={"detector": "model_artifact_detector", "extension": ext}
            )
            findings.append(vuln)

        # Config check in config.json
        if path_obj.name.lower() == "config.json":
            if '"auto_map"' in code_content or '"custom_code"' in code_content:
                vuln = Vulnerability(
                    id="MODEL-CUSTOM-CODE-001",
                    title="Model Config Specifies Remote Custom Execution Code",
                    category=VulnerabilityCategory.LLM05_SUPPLY_CHAIN,
                    severity=Severity.CRITICAL,
                    description="HuggingFace model config.json contains 'auto_map' or remote custom code execution definitions. Loading with trust_remote_code=True executes arbitrary code.",
                    file_path=file_path,
                    line_number=1,
                    column_number=1,
                    code_snippet=code_content[:200],
                    remediation="Inspect custom model code manually before running and avoid using `trust_remote_code=True` on untrusted checkpoints.",
                    cwe_id="CWE-94",
                    owasp_id="LLM05:2025-Supply-Chain",
                    confidence=0.95,
                    metadata={"detector": "model_artifact_detector", "rule_id": "MODEL-CUSTOM-CODE-001"}
                )
                findings.append(vuln)

        return findings
