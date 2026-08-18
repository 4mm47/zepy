# Contributing to ZEPY

Thank you for your interest in improving **ZEPY**! We welcome contributions to expand our rule database, improve AST and regex detection accuracy, and enhance the GUI/CLI experience.

---

## 🛠️ Development Setup

1. **Fork and Clone the Repository**
```bash
git clone https://github.com/4mm47/zepy.git
cd zepy
```

2. **Create a Virtual Environment**
```bash
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

3. **Install Dependencies in Editable Mode**
```bash
pip install -e .
```

4. **Run the Test Suite**
```bash
python -m unittest discover -s zepy/tests
```

---

## 🛡️ Adding a New Detection Rule

To register a new security rule in ZEPY:
1. Open `zepy/rules/definitions.py`.
2. Define a new `RuleDefinition` with unique ID, title, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), CWE ID, OWASP LLM ID, and good/bad code examples.
3. Implement AST detection logic in `zepy/detectors/ast_detector.py` or regex pattern in `zepy/detectors/regex_detector.py`.
4. Add unit test cases in `zepy/tests/test_detectors.py`.

---

## 📋 Pull Request Guidelines

- Ensure all existing and new unit tests pass cleanly.
- Maintain comprehensive comments and type annotations.
- Provide a clear PR description explaining the vulnerability addressed and test results.
