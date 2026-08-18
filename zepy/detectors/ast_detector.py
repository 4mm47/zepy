"""
Zepy - AI Vulnerability Detection Framework
AST Detector: Deep Python Abstract Syntax Tree Semantic Analyzer
"""

import ast
from typing import List, Optional, Any, Set
from zepy.detectors.base import BaseDetector
from zepy.core.models import Vulnerability, Severity, VulnerabilityCategory
from zepy.rules.definitions import RULES_DATABASE


class AstSecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, code_content: str, detector: BaseDetector):
        self.file_path = file_path
        self.code_content = code_content
        self.detector = detector
        self.vulnerabilities: List[Vulnerability] = []
        self.imported_modules: Set[str] = set()
        self.imported_names: dict[str, str] = {}  # alias -> original

    def _get_call_func_name(self, node: ast.Call) -> str:
        """Extract full dotted name from ast.Call func."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            curr: Any = node.func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    def _create_vuln(self, rule_id: str, line_no: int, col_no: int = 1, custom_desc: Optional[str] = None) -> None:
        rule = RULES_DATABASE.get(rule_id)
        if not rule:
            return
        
        snippet = self.detector.extract_snippet(self.code_content, line_no)
        vuln = Vulnerability(
            id=f"{rule.id}-{line_no}",
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            description=custom_desc or rule.description,
            file_path=self.file_path,
            line_number=line_no,
            column_number=col_no,
            code_snippet=snippet,
            remediation=rule.remediation,
            cwe_id=rule.cwe_id,
            owasp_id=rule.owasp_id,
            confidence=0.98,
            metadata={"detector": "ast_detector", "rule_id": rule.id}
        )
        self.vulnerabilities.append(vuln)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imported_modules.add(alias.name)
            if alias.asname:
                self.imported_names[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        self.imported_modules.add(mod)
        for alias in node.names:
            full_name = f"{mod}.{alias.name}" if mod else alias.name
            target = alias.asname or alias.name
            self.imported_names[target] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_func_name(node)
        resolved_name = self.imported_names.get(func_name, func_name)

        # 1. Unsafe Pickle Deserialization
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load") or \
           resolved_name in ("pickle.loads", "pickle.load"):
            self._create_vuln("AST-DESER-001", node.lineno, node.col_offset)

        # 2. Insecure PyTorch Model Loading (torch.load)
        elif func_name in ("torch.load", "load") and ("torch" in self.imported_modules or "torch.load" in resolved_name or func_name == "torch.load"):
            # Check keywords for weights_only=True
            weights_only_present = False
            for kw in node.keywords:
                if kw.arg == "weights_only":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        weights_only_present = True
                    elif isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                        weights_only_present = True

            if not weights_only_present:
                self._create_vuln(
                    "AST-DESER-002",
                    node.lineno,
                    node.col_offset,
                    "torch.load() called without weights_only=True. Enables arbitrary code execution from malicious AI checkpoints."
                )

        # 3. NumPy allow_pickle=True
        elif func_name in ("np.load", "numpy.load") or "numpy.load" in resolved_name:
            for kw in node.keywords:
                if kw.arg == "allow_pickle" and getattr(kw.value, "value", None) is True:
                    self._create_vuln("AST-DESER-003", node.lineno, node.col_offset)

        # 4. Joblib load
        elif func_name in ("joblib.load",) or "joblib.load" in resolved_name:
            self._create_vuln("AST-DESER-003", node.lineno, node.col_offset)

        # 5. YAML Unsafe Load
        elif func_name in ("yaml.unsafe_load",) or (func_name == "yaml.load"):
            # Check Loader
            safe = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    val_str = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                    if "SafeLoader" in val_str or "safe_load" in val_str:
                        safe = True
            if not safe and func_name == "yaml.load":
                self._create_vuln("AST-DESER-004", node.lineno, node.col_offset)
            elif func_name == "yaml.unsafe_load":
                self._create_vuln("AST-DESER-004", node.lineno, node.col_offset)

        # 6. Dynamic Code Execution: eval / exec
        elif func_name in ("eval", "exec"):
            # Check if executing LLM response content
            arg_str = ast.unparse(node.args[0]) if (hasattr(ast, "unparse") and node.args) else ""
            if any(k in arg_str.lower() for k in ["response", "llm", "completion", "message.content", "chat", "generated"]):
                self._create_vuln("AST-LLMOUT-001", node.lineno, node.col_offset)
            else:
                self._create_vuln("AST-EXEC-001", node.lineno, node.col_offset)

        # 7. Subprocess shell=True & os.system
        elif func_name in ("os.system", "os.popen"):
            self._create_vuln("AST-EXEC-002", node.lineno, node.col_offset)

        elif func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                    self._create_vuln(
                        "AST-EXEC-002",
                        node.lineno,
                        node.col_offset,
                        f"{func_name}() called with shell=True. Vulnerable to command injection."
                    )

        # 8. Insecure Randomness in Security Context
        elif func_name in ("random.random", "random.randint", "random.choice", "random.randrange"):
            # If used inside a function or variable named token, secret, key, session, salt
            call_ctx = ast.unparse(node) if hasattr(ast, "unparse") else ""
            # Handled when visiting parent assign if needed

        # 9. Flask / Web App debug=True
        elif func_name.endswith(".run") or func_name == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and getattr(kw.value, "value", None) is True:
                    self._create_vuln("AST-DEBUG-001", node.lineno, node.col_offset)

        # 10. Agent Tool Unsafe Registration
        if any(tool_keyword in func_name.lower() for tool_keyword in ["register_tool", "add_tool", "tool_executor"]):
            for kw in node.keywords:
                if kw.arg in ["auto_approve", "dangerous_allow_all", "unrestricted", "skip_confirmation"] and getattr(kw.value, "value", None) is True:
                    self._create_vuln("AST-AGENT-001", node.lineno, node.col_offset)

        # 11. SQL Injection via LLM Output
        if any(sql_func in func_name.lower() for sql_func in ["execute", "raw_sql", "execute_query"]):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.JoinedStr):  # f-string in query
                    f_str_content = ast.unparse(first_arg) if hasattr(ast, "unparse") else ""
                    if any(kw in f_str_content.lower() for kw in ["llm", "response", "output", "prompt", "user_input", "generated"]):
                        self._create_vuln("AST-LLMOUT-002", node.lineno, node.col_offset)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Check for weak random assigned to security identifiers
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_lower = target.id.lower()
                if any(sec_term in name_lower for sec_term in ["token", "secret", "session_id", "auth_key", "salt", "nonce", "otp"]):
                    val_str = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
                    if "random." in val_str:
                        self._create_vuln("AST-RAND-001", node.lineno, target.col_offset)
        self.generic_visit(node)


class AstDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="AST Semantic Security Detector",
            description="Analyzes Python AST structures to detect unsafe deserialization, dynamic code execution, and unconstrained agent tools."
        )

    def scan_code(self, file_path: str, code_content: str) -> List[Vulnerability]:
        if not file_path.endswith((".py", ".pyw")):
            return []

        try:
            tree = ast.parse(code_content, filename=file_path)
            visitor = AstSecurityVisitor(file_path, code_content, self)
            visitor.visit(tree)
            return visitor.vulnerabilities
        except SyntaxError:
            # File might be incomplete or Python 2 syntax; gracefully skip AST parse
            return []
        except Exception:
            return []
