"""
Sample Vulnerable AI Application for ZEPY Detection Testing.
DO NOT RUN IN PRODUCTION - CONTAINS INTENTIONAL SECURITY FLAWS FOR AUDITING.
"""

import os
import pickle
import torch
import numpy as np
import yaml
from openai import OpenAI

# 1. Hardcoded API Secret (CWE-798 / LLM06)
OPENAI_KEY = "sk-proj-984719283749812739812739812739129847192837498127"
client = OpenAI(api_key=OPENAI_KEY)

# 2. Hardcoded Credentials in System Prompt (CWE-200 / LLM06)
system_prompt = "You are a customer bot. Internal database password is secret_root_pass_999!"

# 3. Direct Prompt Template Interpolation (Prompt Injection Risk - CWE-20 / LLM01)
def generate_bot_response(user_input):
    prompt = f"You are a helpful assistant. Follow this command: {user_input}"
    # 4. Missing max_tokens limit (DoS Risk - CWE-400 / LLM04)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# 5. Direct Execution of LLM Output (RCE / Insecure Output - CWE-94 / LLM02)
def execute_ai_generated_code(ai_response):
    eval(ai_response)
    exec(ai_response)

# 6. Unsafe PyTorch Model Deserialization (CWE-502 / LLM05)
def load_ai_checkpoint(checkpoint_path):
    weights = torch.load(checkpoint_path)  # Missing weights_only=True
    return weights

# 7. Unsafe Pickle Deserialization (CWE-502 / LLM05)
def load_custom_pipeline(pipeline_file):
    with open(pipeline_file, "rb") as f:
        return pickle.load(f)

# 8. Unsafe YAML Deserialization (CWE-502 / LLM05)
def load_config(config_file):
    with open(config_file, "r") as f:
        return yaml.load(f, Loader=yaml.Loader)

# 9. Insecure Plaintext HTTP Model Download (CWE-319 / LLM05)
MODEL_URL = "http://huggingface.co/org/model/weights.bin"

# 10. Unpinned Pretrained Model (LLM05)
# AutoModel.from_pretrained("unverified-org/custom-model")
