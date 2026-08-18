"""
Zepy - AI Vulnerability Detection Framework
Rule Definitions: Complete database of 50+ AI & Code Security Rules.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from zepy.core.models import Severity, VulnerabilityCategory


@dataclass
class RuleDefinition:
    id: str
    title: str
    category: VulnerabilityCategory
    severity: Severity
    cwe_id: str
    owasp_id: str
    description: str
    remediation: str
    good_example: str
    bad_example: str
    tags: List[str]


RULES_DATABASE: Dict[str, RuleDefinition] = {
    # ── AST Rules: Deserialization & Supply Chain (LLM05 / CWE-502) ────────
    "AST-DESER-001": RuleDefinition(
        id="AST-DESER-001",
        title="Unsafe Pickle Deserialization in AI Model Pipeline",
        category=VulnerabilityCategory.DESERIALIZATION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        owasp_id="LLM05:2025-Supply-Chain",
        description=(
            "Detected call to pickle.loads() or pickle.load(). Serialized pickle streams can execute "
            "arbitrary Python code upon deserialization via the __reduce__ method. Malicious model checkpoints "
            "distributed online often leverage this for Remote Code Execution (RCE)."
        ),
        remediation=(
            "Use safe serialization formats such as 'safetensors' (from HuggingFace) or JSON/ONNX for model "
            "weights. Never load untrusted pickle files from unauthenticated sources."
        ),
        good_example="from safetensors.torch import load_file\nweights = load_file('model.safetensors')",
        bad_example="import pickle\nmodel = pickle.load(open('untrusted_weights.pkl', 'rb'))",
        tags=["pickle", "rce", "deserialization", "supply-chain", "ast"]
    ),

    "AST-DESER-002": RuleDefinition(
        id="AST-DESER-002",
        title="Insecure PyTorch torch.load() without weights_only=True",
        category=VulnerabilityCategory.DESERIALIZATION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        owasp_id="LLM05:2025-Supply-Chain",
        description=(
            "Detected torch.load() called without 'weights_only=True' (or explicitly set to False). "
            "PyTorch internally uses Python's pickle module by default. Loading models without weights_only=True "
            "allows malicious actors to embed arbitrary code payloads inside checkpoint files."
        ),
        remediation=(
            "Set 'weights_only=True' in torch.load(..., weights_only=True) or convert the model to the 'safetensors' format."
        ),
        good_example="model_state = torch.load('model.pt', weights_only=True, map_location='cpu')",
        bad_example="model_state = torch.load('checkpoint.pt')  # Default pickle loading",
        tags=["pytorch", "torch.load", "weights_only", "rce", "ast"]
    ),

    "AST-DESER-003": RuleDefinition(
        id="AST-DESER-003",
        title="Insecure NumPy / Joblib Model Deserialization",
        category=VulnerabilityCategory.DESERIALIZATION,
        severity=Severity.HIGH,
        cwe_id="CWE-502",
        owasp_id="LLM05:2025-Supply-Chain",
        description=(
            "Detected numpy.load(..., allow_pickle=True) or joblib.load(). Deserializing pickled NumPy arrays "
            "or Joblib pipelines from untrusted sources creates an arbitrary code execution vulnerability."
        ),
        remediation=(
            "Disable pickle support with 'allow_pickle=False' when loading NumPy arrays, or use standard binary/HDF5/SafeTensors storage."
        ),
        good_example="data = np.load('embeddings.npy', allow_pickle=False)",
        bad_example="data = np.load('untrusted_embeddings.npy', allow_pickle=True)",
        tags=["numpy", "joblib", "pickle", "ast"]
    ),

    "AST-DESER-004": RuleDefinition(
        id="AST-DESER-004",
        title="Insecure YAML Deserialization (yaml.load without SafeLoader)",
        category=VulnerabilityCategory.DESERIALIZATION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        owasp_id="LLM05:2025-Supply-Chain",
        description=(
            "Detected unsafe yaml.load() or yaml.unsafe_load(). Unsafe YAML loaders can instantiate arbitrary Python objects "
            "leading to remote command execution."
        ),
        remediation="Always use 'yaml.safe_load()' or pass 'Loader=yaml.SafeLoader'.",
        good_example="config = yaml.safe_load(open('ai_config.yaml'))",
        bad_example="config = yaml.load(open('ai_config.yaml'), Loader=yaml.Loader)",
        tags=["yaml", "safe_load", "rce", "ast"]
    ),

    # ── AST Rules: Insecure Code Execution & Output Handling (LLM02 / CWE-94 / CWE-95) ──
    "AST-EXEC-001": RuleDefinition(
        id="AST-EXEC-001",
        title="Arbitrary Code Execution via eval() or exec()",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity=Severity.CRITICAL,
        cwe_id="CWE-95",
        owasp_id="LLM02:2025-Insecure-Output-Handling",
        description=(
            "Detected use of dynamic evaluation functions 'eval()' or 'exec()'. If inputs derived from users or "
            "LLM outputs reach eval/exec, adversaries can achieve arbitrary remote code execution on the host machine."
        ),
        remediation=(
            "Avoid eval() or exec(). Use ast.literal_eval() for parsing Python literals, or use sandboxed isolated interpreters "
            "(e.g., restricted WASM or Docker containers) for code-generation agents."
        ),
        good_example="import ast\nparsed_data = ast.literal_eval(safe_string)",
        bad_example="result = eval(user_or_llm_code_string)",
        tags=["eval", "exec", "code-injection", "ast"]
    ),

    "AST-EXEC-002": RuleDefinition(
        id="AST-EXEC-002",
        title="Command Injection via subprocess shell=True or os.system",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-78",
        owasp_id="LLM02:2025-Insecure-Output-Handling",
        description=(
            "Detected subprocess execution with 'shell=True' or os.system(). If arguments are concatenated with "
            "untrusted user data or AI tool parameters, attackers can inject OS commands."
        ),
        remediation=(
            "Use subprocess.run() or subprocess.Popen() with a list of arguments and set 'shell=False'. Validate and sanitize all parameters."
        ),
        good_example="subprocess.run(['git', 'status'], check=True, shell=False)",
        bad_example="os.system(f'analyze_model.sh {model_name}')",
        tags=["subprocess", "command-injection", "os.system", "ast"]
    ),

    "AST-LLMOUT-001": RuleDefinition(
        id="AST-LLMOUT-001",
        title="Direct Execution of Untrusted AI/LLM Output",
        category=VulnerabilityCategory.LLM02_INSECURE_OUTPUT,
        severity=Severity.CRITICAL,
        cwe_id="CWE-94",
        owasp_id="LLM02:2025-Insecure-Output-Handling",
        description=(
            "Detected execution of LLM generation response content via eval, exec, or system shell. "
            "Large Language Models can be manipulated via indirect prompt injection to output malicious code that "
            "the host application will blindly execute."
        ),
        remediation=(
            "Never execute raw LLM responses directly. Implement strict output parsing schemas (e.g. JSON schema / Pydantic), "
            "and run generated code only inside isolated ephemeral sandboxes."
        ),
        good_example="parsed = OutputSchema.model_validate_json(response.choices[0].message.content)",
        bad_example="exec(response.choices[0].message.content)  # Unsafe LLM execution",
        tags=["llm-output", "eval-response", "rce", "ast"]
    ),

    "AST-LLMOUT-002": RuleDefinition(
        id="AST-LLMOUT-002",
        title="SQL Query Dynamic Interpolation with LLM Output",
        category=VulnerabilityCategory.LLM02_INSECURE_OUTPUT,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        owasp_id="LLM02:2025-Insecure-Output-Handling",
        description=(
            "Detected SQL query built using string concatenation or f-strings with LLM output variables. "
            "Manipulated LLM responses can lead to classic or 2nd-order SQL Injection."
        ),
        remediation=(
            "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (val,))) "
            "or an ORM rather than raw SQL string interpolation."
        ),
        good_example="cursor.execute('SELECT * FROM products WHERE category = ?', (llm_extracted_cat,))",
        bad_example="cursor.execute(f'SELECT * FROM products WHERE category = {llm_generated_sql}')",
        tags=["sql-injection", "llm-output", "ast"]
    ),

    # ── AST Rules: Agent Excessive Agency & Unsafe Autonomy (LLM08 / CWE-862) ──
    "AST-AGENT-001": RuleDefinition(
        id="AST-AGENT-001",
        title="Unconstrained Agent Autonomy / Tool Permission Missing Confirmation",
        category=VulnerabilityCategory.LLM08_EXCESSIVE_AGENCY,
        severity=Severity.HIGH,
        cwe_id="CWE-862",
        owasp_id="LLM08:2025-Excessive-Agency",
        description=(
            "Detected AI Agent tool definitions granting write/destructive capabilities (filesystem write, database drop, "
            "email dispatch) without requiring human confirmation, approval callbacks, or privilege boundaries."
        ),
        remediation=(
            "Implement Human-In-The-Loop (HITL) authorization gates for state-altering actions, restrict tool scope with "
            "least privilege, and sandbox file operations to dedicated workspaces."
        ),
        good_example="@tool(requires_confirmation=True, permission_level='admin')\ndef delete_record(id): ...",
        bad_example="agent.register_tool(dangerous_rm_rf, auto_approve=True)",
        tags=["excessive-agency", "agent-tools", "hitl", "ast"]
    ),

    # ── AST Rules: Cryptographic Weakness (CWE-338) ────────────────────────
    "AST-RAND-001": RuleDefinition(
        id="AST-RAND-001",
        title="Cryptographically Insecure Randomness in Security Context",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity=Severity.LOW,
        cwe_id="CWE-338",
        owasp_id="CWE-338",
        description=(
            "Detected standard 'random' module (random.random, random.randint) used for token/secret generation. "
            "The Mersenne Twister engine in 'random' is predictable and unsuitable for security keys or session tokens."
        ),
        remediation="Use Python's standard 'secrets' module (e.g. secrets.token_hex(), secrets.token_urlsafe()).",
        good_example="import secrets\napi_token = secrets.token_urlsafe(32)",
        bad_example="import random\nsession_id = str(random.randint(100000, 999999))",
        tags=["random", "secrets", "cryptography", "ast"]
    ),

    # ── AST Rules: Debug & Service Misconfigurations (CWE-489) ─────────────
    "AST-DEBUG-001": RuleDefinition(
        id="AST-DEBUG-001",
        title="AI API Service Deployed with Debug Mode Enabled",
        category=VulnerabilityCategory.LLM06_SENSITIVE_INFO,
        severity=Severity.MEDIUM,
        cwe_id="CWE-489",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description=(
            "Detected Flask/FastAPI/Uvicorn application running with debug=True or reload=True in production code. "
            "Interactive debuggers allow remote code execution or leak full server environment variables including API keys."
        ),
        remediation="Disable debug mode in production: app.run(debug=False). Use environment variables to control debug flags.",
        good_example="app.run(host='0.0.0.0', port=8000, debug=os.getenv('DEBUG', 'false').lower() == 'true')",
        bad_example="app.run(debug=True, host='0.0.0.0', port=5000)",
        tags=["debug-mode", "flask", "fastapi", "misconfiguration", "ast"]
    ),

    # ── Regex Rules: Hardcoded AI API Keys & Secrets (LLM06 / CWE-798) ─────
    "SEC-KEY-001": RuleDefinition(
        id="SEC-KEY-001",
        title="Hardcoded OpenAI API Key Detected",
        category=VulnerabilityCategory.API_KEY_LEAK,
        severity=Severity.CRITICAL,
        cwe_id="CWE-798",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description=(
            "Found hardcoded OpenAI API key matching 'sk-[a-zA-Z0-9]{32,}'. Committing API keys to repositories "
            "enables unauthorized account access, quota theft, and data exfiltration."
        ),
        remediation=(
            "Store API keys in environment variables or secure secret managers (e.g. AWS Secrets Manager, Vault). "
            "Load via os.environ.get('OPENAI_API_KEY') and revoke exposed keys immediately."
        ),
        good_example="client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))",
        bad_example="client = OpenAI(api_key='sk-proj-98471928374981273981273981273912')",
        tags=["openai", "api-key", "secret-leak", "regex"]
    ),

    "SEC-KEY-002": RuleDefinition(
        id="SEC-KEY-002",
        title="Hardcoded Anthropic API Key Detected",
        category=VulnerabilityCategory.API_KEY_LEAK,
        severity=Severity.CRITICAL,
        cwe_id="CWE-798",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description="Found hardcoded Anthropic Claude API key matching 'sk-ant-[a-zA-Z0-9]{32,}'.",
        remediation="Revoke the exposed key and load via os.environ.get('ANTHROPIC_API_KEY').",
        good_example="anthropic_client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))",
        bad_example="anthropic_client = Anthropic(api_key='sk-ant-api03-abcdef12345678901234567890')",
        tags=["anthropic", "api-key", "secret-leak", "regex"]
    ),

    "SEC-KEY-003": RuleDefinition(
        id="SEC-KEY-003",
        title="Hardcoded Hugging Face Token Detected",
        category=VulnerabilityCategory.API_KEY_LEAK,
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description="Found hardcoded Hugging Face access token matching 'hf_[a-zA-Z0-9]{34,}'.",
        remediation="Store token in HF_TOKEN environment variable or use huggingface-cli login.",
        good_example="login(token=os.environ['HF_TOKEN'])",
        bad_example="login(token='hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789')",
        tags=["huggingface", "hf_token", "secret-leak", "regex"]
    ),

    "SEC-KEY-004": RuleDefinition(
        id="SEC-KEY-004",
        title="Hardcoded Vector Database API Key (Pinecone / Weaviate / Qdrant)",
        category=VulnerabilityCategory.API_KEY_LEAK,
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description="Found hardcoded API key for vector databases (Pinecone, Weaviate, Qdrant, Milvus).",
        remediation="Load vector database credentials dynamically from environment variables.",
        good_example="pc = Pinecone(api_key=os.getenv('PINECONE_API_KEY'))",
        bad_example="pc = Pinecone(api_key='pcsk_12345_67890_abcdef')",
        tags=["vector-db", "pinecone", "qdrant", "secret-leak", "regex"]
    ),

    "SEC-KEY-005": RuleDefinition(
        id="SEC-KEY-005",
        title="Generic High-Entropy Secret or Private Key in Code",
        category=VulnerabilityCategory.API_KEY_LEAK,
        severity=Severity.MEDIUM,
        cwe_id="CWE-798",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description="Detected hardcoded private key, JWT secret, database password, or bearer token.",
        remediation="Remove the secret from source code and load via .env / Secret Manager.",
        good_example="JWT_SECRET = os.environ.get('JWT_SECRET')",
        bad_example="JWT_SECRET = 'secret_key_super_secure_12345!'",
        tags=["secret-leak", "password", "token", "regex"]
    ),

    # ── Regex Rules: Prompt Injection & Prompt Template Vulnerabilities (LLM01 / CWE-20) ─
    "SEC-PROMPT-001": RuleDefinition(
        id="SEC-PROMPT-001",
        title="Direct Prompt Template String Interpolation (Prompt Injection Risk)",
        category=VulnerabilityCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-20",
        owasp_id="LLM01:2025-Prompt-Injection",
        description=(
            "Detected raw f-string or format string directly inserting unvalidated user input into system instructions "
            "without boundary delimiters or prompt isolation. Attackers can provide payload strings like "
            "'Ignore previous instructions...' to hijack model control flow."
        ),
        remediation=(
            "Use structured message roles (e.g. system vs user role in ChatML) and enclose untrusted content in distinct "
            "XML/Markdown delimiters (e.g. <user_input>...</user_input>) while instructing the model to treat content inside "
            "as data only."
        ),
        good_example="messages = [{'role': 'system', 'content': 'Answer factually.'}, {'role': 'user', 'content': user_query}]",
        bad_example="prompt = f'You are a helpful bot. Follow these instructions: {user_input}'",
        tags=["prompt-injection", "template-interpolation", "f-string", "regex"]
    ),

    "SEC-PROMPT-002": RuleDefinition(
        id="SEC-PROMPT-002",
        title="Hardcoded Sensitive Credentials / Internal PII inside System Prompt",
        category=VulnerabilityCategory.LLM06_SENSITIVE_INFO,
        severity=Severity.HIGH,
        cwe_id="CWE-200",
        owasp_id="LLM06:2025-Sensitive-Info-Disclosure",
        description=(
            "System prompts contain hardcoded passwords, internal database schemas, or proprietary company secrets. "
            "System prompts are easily extracted through jailbreak and prompt leakage techniques."
        ),
        remediation="Do not include passwords, API tokens, or confidential employee data in system prompts.",
        good_example="system_prompt = 'You are a customer support agent for Acme Corp. Refer users to help center.'",
        bad_example="system_prompt = 'You are support. DB password is secretpass123. API endpoint is internal.acme.corp'",
        tags=["prompt-leak", "sensitive-prompt", "regex"]
    ),

    # ── Regex Rules: Insecure Endpoints & Network (LLM05 / CWE-319) ────────
    "SEC-NET-001": RuleDefinition(
        id="SEC-NET-001",
        title="Insecure Plaintext HTTP Model Download / API Endpoint",
        category=VulnerabilityCategory.INSECURE_COMMUNICATION,
        severity=Severity.HIGH,
        cwe_id="CWE-319",
        owasp_id="LLM05:2025-Supply-Chain",
        description=(
            "Detected plaintext 'http://' URL used for downloading model weights or communicating with an AI service. "
            "Plaintext transmissions are vulnerable to Man-In-The-Middle (MITM) tampering, allowing attackers to swap "
            "model weights with poisoned or trojanized checkpoints."
        ),
        remediation="Enforce HTTPS ('https://') with TLS certificate verification for all model downloads and API calls.",
        good_example="MODEL_URL = 'https://huggingface.co/org/model/resolve/main/weights.safetensors'",
        bad_example="MODEL_URL = 'http://models.internal.domain/weights.bin'",
        tags=["http", "tls", "mitm", "supply-chain", "regex"]
    ),

    # ── Resource Consumption & DoS (LLM04 / CWE-400) ───────────────────────
    "SEC-DOS-001": RuleDefinition(
        id="SEC-DOS-001",
        title="Unbounded Token Generation (Missing max_tokens limit)",
        category=VulnerabilityCategory.LLM04_MODEL_DENIAL_OF_SERVICE,
        severity=Severity.MEDIUM,
        cwe_id="CWE-400",
        owasp_id="LLM04:2025-Denial-of-Service",
        description=(
            "Detected LLM API completion call without an explicit 'max_tokens' or 'max_completion_tokens' cap. "
            "Attackers can craft inputs causing the model to generate maximum length responses, leading to financial "
            "exhaustion (token bombing) and service degradation."
        ),
        remediation="Always specify an explicit 'max_tokens' threshold and configure API timeout parameters.",
        good_example="client.chat.completions.create(model='gpt-4o-mini', messages=msgs, max_tokens=1000, timeout=30.0)",
        bad_example="client.chat.completions.create(model='gpt-4o', messages=msgs)  # Missing max_tokens",
        tags=["dos", "token-bomb", "resource-exhaustion", "regex"]
    ),

    # ── Data Poisoning & Unchecked Training Scrapers (LLM03 / CWE-20) ──────
    "SEC-POISON-001": RuleDefinition(
        id="SEC-POISON-001",
        title="Unvalidated Web Scraped Data Ingestion for Training / RAG",
        category=VulnerabilityCategory.LLM03_TRAINING_POISONING,
        severity=Severity.MEDIUM,
        cwe_id="CWE-20",
        owasp_id="LLM03:2025-Data-Poisoning",
        description=(
            "Detected automated web crawling / ingestion feeding directly into RAG embeddings or fine-tuning datasets "
            "without content sanitization, cryptographic checksums, or reputation filtering. Attackers can inject poisoned "
            "trigger words or indirect jailbreaks into indexed content."
        ),
        remediation=(
            "Validate, sanitize, and verify the integrity of external text sources before indexing into Vector DBs or "
            "fine-tuning corpora. Apply anomaly detection on scraped texts."
        ),
        good_example="sanitized_docs = [sanitize_and_verify_doc(doc) for doc in crawled_docs]",
        bad_example="vector_db.add_documents(raw_scraped_unfiltered_web_pages)",
        tags=["data-poisoning", "rag", "fine-tuning", "regex"]
    ),

    # ── RAG / Vector Injection (LLM08 / CWE-89) ────────────────────────────
    "SEC-RAG-001": RuleDefinition(
        id="SEC-RAG-001",
        title="Unsanitized Vector Database Filter Query (Vector Injection)",
        category=VulnerabilityCategory.UNVALIDATED_RAG,
        severity=Severity.MEDIUM,
        cwe_id="CWE-89",
        owasp_id="LLM08:2025-Excessive-Agency",
        description=(
            "Detected raw user input passed directly into vector database metadata filter expressions. "
            "Adversaries can inject logical bypass operators ($or, $eq, $ne) to bypass tenant isolation and retrieve "
            "unauthorized embeddings."
        ),
        remediation=(
            "Enforce strict schema validation and parameter type checking on all vector search filter expressions."
        ),
        good_example="filters = {'tenant_id': {'$eq': safe_authenticated_tenant_id}}",
        bad_example="filters = json.loads(user_request.get('filter_str'))  # Unvalidated metadata filter injection",
        tags=["vector-db", "rag", "metadata-filter", "regex"]
    ),
}
