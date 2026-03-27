# Malicious Package Detection: Project Architecture & Workflow

This document outlines the step-by-step phases of the Malicious Package Detection system, detailing the input, processing, and output of each stage.

---

## 🏗️ Phase 1: Package Ingestion (Download & Extract)
**Module:** `utils/downloader.py`

| Input | Process | Output |
| :--- | :--- | :--- |
| `package_name`, `registry` (npm/pypi) | Fetches the latest tarball/zip from registries using `requests`. | A local temporary directory containing the extracted source code. |

---

## 🔍 Phase 2: Static Analysis (AST Parsing)
**Module:** `parser/ast_parser.py`

| Input | Process | Output |
| :--- | :--- | :--- |
| Source files (`.py`, `.js`, `package.json`) | Uses `ast` (Python) and regex-based tokenization (JS) to identify sensitive calls. | A list of raw behavioral tokens (e.g., `IMPORT_OS`, `CALL_SUBPROCESS.RUN`). |

---

## 🛠️ Phase 3: Behavior Extraction & Normalization
**Module:** `parser/behavior_extractor.py`

| Input | Process | Output |
| :--- | :--- | :--- |
| Raw behavioral tokens | Filters high-risk indicators and converts them into structured behavior tags and a natural language description. | A list of specific behavior tags and a descriptive string for RAG comparison. |

---

## 🤖 Phase 4: RAG Match (Vector Database)
**Module:** `rag/vector_db.py`

| Input | Process | Output |
| :--- | :--- | :--- |
| Natural language behavior description | Generates a vector embedding and performs a cosine similarity search against `patterns.json`. | The most relevant known threat pattern and a similarity score (0.0 - 1.0). |

---

## 🧪 Phase 4b: Dynamic Sandbox Monitoring
**Modules:** `detector/sandbox.py` & `utils/sandbox_wrapper.py`

| Input | Process | Output |
| :--- | :--- | :--- |
| Extracted package directory | Executes the package in an isolated Docker container. Uses monkey patching to intercept runtime calls to `os`, `subprocess`, `socket`, and `requests`. | A JSON log of confirmed runtime behavioral events (e.g., actual shell commands executed). |

---

## 🧠 Phase 5: Risk Assessment & Reasoning (LLM)
**Module:** `llm/analyzer.py`

| Input | Process | Output |
| :--- | :--- | :--- |
| Behaviors + RAG Match Results | Applies a weighted risk scoring system and generates a structured reporting reason using response templates. | A final JSON analysis: `verdict`, `score`, `reasoning`, `confidence` level. |

---

## 🖥️ Phase 6: Presentation (CLI & API)
**Modules:** `main.py` & `server.py`

- **CLI (`main.py`):** Uses `rich` to display a beautiful, colored report with tables and panels.
- **API (`server.py`):** Uses `FastAPI` and `uvicorn` to expose the detection engine via REST endpoints.

---

## 📚 Technical Stack

## 🛠️ Technical Stack & Selection Rationale

### Libraries Used:
1.  **Network/Package Handling:** `requests`
    *   *Why?* It's the industry standard for Python HTTP requests. It's synchronous (sufficient for our ingestion pace) and extremely reliable for downloading large binary files like tarballs.
2.  **Machine Learning:** `sentence-transformers` (Embeddings), `numpy` / `scikit-learn` (Similarity)
    *   *Why?* `sentence-transformers` provides a high-level API to state-of-the-art transformer models. We use `numpy` and `scikit-learn` for similarity because they are highly optimized for vector mathematics.
3.  **Parsing:** `ast` (Python standard library)
    *   *Why?* We chose the standard `ast` module to ensure zero external dependencies for parsing. It is extremely fast and robust for static analysis across different Python versions.
4.  **Web/API:** `fastapi`, `uvicorn`, `pydantic`
    *   *Why?* FastAPI is the modern standard for high-performance Python APIs. Combined with Pydantic for data validation, it ensures the detection engine is production-ready and type-safe.
5.  **CLI UI:** `rich`
    *   *Why?* Essential for the "Security Tool" persona. It allows us to render complex data structures (like risk tables and reasoning summaries) into a clear, visually impactful CLI report.

---

### Models (LLMs):
-   **Embedding Model:** `all-MiniLM-L6-v2`
    *   *Selection Rationale:* 
        1. **Size:** At ~80MB, it's small enough to load quickly on cold starts.
        2. **Speed:** It can encode hundreds of text snippets in milliseconds on a standard CPU.
        3. **Local-First:** By using this model, we avoid the latency and cost of external APIs (like OpenAI) while ensuring that sensitive package data never leaves the user's environment.
        4. **Purpose-Fit:** This specific model is fine-tuned for sentence similarity, making it ideal for matching behavior descriptions against a database of known threat patterns.
-   **Reasoning Engine:** Rule-based simulated LLM.
    *   *Selection Rationale:* 
        1. **Deterministic Results:** Risk analysis for security requires predictable, explainable outcomes. A weighted scoring system ensures that if the same behavior is seen, the same risk score is generated.
        2. **No Latency:** Real-time analysis is critical. Using a rule-based generator for the "Reasoning" phase removes the 5-10 second wait time common with large LLM calls.
        3. **Transparency:** Every indicator can be audited directly in `analyzer.py`, unlike "black-box" LLM decisions.

---

## 📂 Project Structure Snapshot
```text
.
├── detector/           # Core engine orchestration
├── llm/                # Risk analysis & reasoning
├── parser/             # AST parsing & behavior extraction
├── rag/                # Vector DB and threat patterns
│   └── patterns.json   # Knowledge base of safe/malicious code
├── utils/              # Package downloaders
├── main.py             # CLI Entrypoint
└── server.py           # API Entrypoint
```
