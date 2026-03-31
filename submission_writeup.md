# Hackathon Submission — Project Experience Write-up

## Project: AI Secure Data Intelligence Platform

---

### Problem Solved

Modern engineering teams routinely expose sensitive data through logs, config files, chat messages, SQL queries, and documents — often without realizing it. API keys, passwords, tokens, and PII leak through debugging workflows, error messages, and poorly handled log pipelines.

**The AI Secure Data Intelligence Platform** solves this by acting as an intelligent security gateway that scans any content in real time, detects risks with high precision, and generates actionable AI insights — before sensitive data reaches unintended recipients.

---

### Approach and Design

The system is built around a **four-layer pipeline**:

1. **Input Layer** — Accepts text, file uploads (PDF/TXT/LOG), SQL queries, chat messages, and raw logs through a unified FastAPI REST API.

2. **Detection Engine** — A two-stage detection system:
   - **Stage 1 (Regex)**: 14 pattern categories (API keys, passwords, tokens, private keys, SQL injection, stack traces, connection strings, IPs, emails, phone numbers) with line-level precision.
   - **Stage 2 (AI)**: Claude claude-opus-4-5 performs contextual analysis — identifying behavioral anomalies like brute-force attempts, debug mode leaks, and patterns the regex layer cannot detect (e.g., semantically suspicious content).

3. **Risk Engine** — Aggregates all findings into a 0–100 risk score with severity classification (SAFE / LOW / MEDIUM / HIGH / CRITICAL).

4. **Policy Engine** — Makes enforcement decisions: mask sensitive values, block critical content, or flag for manual review — configurable per request.

The frontend is a single-file dashboard with a real-time risk meter, annotated log viewer (line-highlighted by risk level), AI insights panel, and drag-and-drop file upload.

---

### Technologies Used

- **Backend**: Python 3.11, FastAPI, Uvicorn, Pydantic v2
- **AI**: Anthropic Claude claude-opus-4-5 (via `anthropic` Python SDK)
- **File Parsing**: PyPDF2 for PDF text extraction
- **Pattern Detection**: Python `re` module — compiled regex patterns
- **Frontend**: Vanilla HTML5 / CSS3 / JavaScript (no build step, zero dependencies)
- **Deployment**: Uvicorn ASGI server; Docker-ready

---

### Challenges Faced

**1. Balancing Regex Precision vs. Recall**  
Regex patterns for credentials must be specific enough to avoid false positives (e.g., matching any long alphanumeric string) while broad enough to catch real-world key formats (AWS, GitHub, Slack, OpenAI, etc.). This required iterating on real leaked credential formats from public datasets.

**2. AI JSON Reliability**  
Claude occasionally returns markdown-wrapped JSON or explanation text alongside the JSON object. Solved with a two-pass parser: strip markdown fences, then `json.loads()` — with graceful fallback if parsing fails.

**3. Log Line Attribution**  
Linking regex findings back to their exact line numbers required tracking line-by-line position during scanning, not just returning raw match objects. This enabled the annotated log viewer to highlight exactly which lines contain risks.

**4. Aggregate Risk Scoring**  
Summing raw finding scores can exceed 100 for heavily compromised logs. Solved by capping at 100 and ensuring the risk level classification is derived from the capped score, not raw findings count.

**5. Stateless File Processing**  
Files must be parsed, scanned, and responded to in a single request cycle without temporary disk storage. PyPDF2 and in-memory byte streams (`io.BytesIO`) made this possible without temp files.

---

### Domain

**AI & Automation Testing** — The platform automates security testing of data pipelines, log outputs, and API content using AI-driven analysis.
