# Malicious Package Detection System (AST + LLM + RAG)

A sophisticated cybersecurity tool designed to identify supply-chain attacks in NPM and PyPI ecosystems using static analysis, behavior sequences, and vector-based retrieval.

---

## Overview

This tool moves beyond simple regex-based heuristic scanners by:
1.  **Parsing** source code into AST (Abstract Syntax Tree).
2.  **Extracting** high-level behavior sequences.
3.  **Comparing** behaviors against known malicious patterns using **RAG** (Retrieval-Augmented Generation) with vector similarity.
4.  **Dynamic Sandboxing**: Executing the package in an isolated Docker container with behavioral monitoring to catch runtime threats.
5.  **Reasoning** about the risk using a **Simulated LLM** that generates high-fidelity explanations based on both static and dynamic findings.

---

## Architecture

-   `parser/`: AST parsing for Python/JS and behavioral extraction logic.
-   `rag/`: Vector database and known malicious pattern storage.
-   `llm/`: Simulated reasoning engine for risk scoring and explanations.
-   `detector/`: Core orchestration engine and Sandbox Manager.
-   `utils/`: Registry downloaders, file system helpers, and the sandbox wrapper.
-   `main.py`: Interactive CLI with rich terminal formatting.

---

## Setup

1.  **Environment** (Python 3.10+):
    ```bash
    pip install -r requirements.txt
    ```

3.  **Docker Desktop** (Required for Dynamic Analysis):
    The tool requires Docker to run the sandbox. Ensure Docker is running.

2.  **Manual Model Download (Optional but recommended)**:
    If using `all-MiniLM-L6-v2` for the first time, it will automatically download from HuggingFace upon first run.

---

## Usage

### Scan NPM Package
```bash
python main.py express --registry npm
```

### Scan PyPI Package
```bash
python main.py requests --registry pypi
```

### Scan Local Directory (Testing)
```bash
# Scan a simulated malicious example
python main.py --local ./tests/malicious_example

# Scan a simulated safe example
python main.py --local ./tests/safe_example
```

# To run server

```bash
uvicorn server:app --reload
```

---

## How Detection Works

1.  **AST Extraction**: The tool parses `.py` and `.js` files. It looks for sensitive API calls like `os.system`, `fetch`, `base64.decode`, and `process.env`.
2.  **Behavior Mapping**: Raw tokens are converted into high-level behaviors:
    -   `CALL_OS.SYSTEM` -> `SHELL_EXECUTION`
    -   `CALL_REQUESTS.POST` + `CALL_ENVIRON` -> `EXFILTRATION_RISK`
3.  **Vector RAG**: These sequences are vectorized and compared against `rag/patterns.json` using cosine similarity.
4.  **Dynamic Analysis (Sandbox)**: The tool spins up an isolated Docker container and intercepts runtime calls (like `os.system` or `socket.connect`) via monkey patching. This catches obfuscated malware that hides from static analysis.
5.  **Simulated LLM Reasoning**: The analyzer evaluates the combination of static behaviors and confirmed runtime events. For example, a network call alone is fine, but a network call confirmed at runtime alongside static environment variable access triggers a **MALICIOUS** verdict with high confidence.

---

# Sample Output

```json
{
  "package_name": "malicious-pkg",
  "registry": "npm",
  "behaviors": ["IMPORT_OS", "CALL_SUBPROCESS.RUN", "NETWORK_REQUEST"],
  "behavior_description": "this code imports sensitive module and executes shell commands...",
  "rag_match": {
    "pattern": { "threat": "Reverse Shell", "description": "Spawns a remote shell..." },
    "score": 0.85
  },
  "dynamic_analysis": [
    { "category": "NETWORK_CONNECTION", "details": { "host": "attacker.com", "port": 80 } }
  ],
  "analysis": {
    "verdict": "MALICIOUS",
    "score": 100,
    "reasoning": "AI ANALYSIS REPORT: ...",
    "confidence": "High",
    "indicators": [
      ["Static: SHELL_EXECUTION", 45], 
      ["Dynamic: Outbound Network Request", 40]
    ]
  }
}
```

## Testing Results

### Malicious Example Result
-   **Detected Behaviors**: SHELL_EXECUTION, NETWORK_REQUEST, ENV_VARIABLE_ACCESS, DATA_ENCODING.
-   **RAG Match**: "Data Exfiltration (Environment Variables)".
-   **Verdict**: MALICIOUS (Score: 85+)

---

## Limitations & Future Work
-   **Contextual Analysis**: Some legitimate DevOps tools (like AWS SDK) use similar behaviors; they require higher confidence thresholds.
-   **Future**: Support for Rust/C++ extensions and advanced kernel-level monitoring.

---

