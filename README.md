# 🛡️ AI Secure Data Intelligence Platform

> **AI Gateway · Data Scanner · Log Analyzer · Risk Engine**

A production-grade security intelligence platform that scans text, files, logs, and SQL for sensitive data, credentials, secrets, and anomalies — powered by regex pattern detection + Claude AI for deep, contextual insights.

---

## ✨ Features

### Multi-Input Support
| Input Type | Description |
|---|---|
| **Text / Chat** | Freeform text, live chat messages, config snippets |
| **Log Files** | `.log`, `.txt` — line-by-line parsing with highlighted viewer |
| **File Upload** | PDF, TXT, LOG with drag & drop support |
| **SQL** | Queries scanned for injection patterns and embedded credentials |

### Detection Engine (14 Pattern Categories)
| Pattern | Risk Level |
|---|---|
| API Keys (AWS, GitHub, Google, OpenAI) | 🟠 High |
| Passwords & Credentials | 🔴 Critical |
| Auth Tokens (GitHub PAT, Slack, Bearer) | 🟠 High |
| Private Keys (RSA, EC, OpenSSH) | 🔴 Critical |
| Database Connection Strings | 🔴 Critical |
| SQL Injection Patterns | 🔴 Critical |
| Stack Traces / Error Leaks | 🟡 Medium |
| Internal IP Addresses | 🟡 Medium |
| Email Addresses | 🟢 Low |
| Phone Numbers | 🟢 Low |

### AI-Powered Analysis (Claude)
- Executive summary of all findings
- Behavioral anomaly detection (brute force, debug leaks)
- Contextual risk insights beyond regex capabilities
- Actionable remediation recommendations

### Risk Engine
- Aggregate risk scoring (0–100)
- Risk classification: SAFE → LOW → MEDIUM → HIGH → CRITICAL

### Policy Engine
- **Mask**: Replace sensitive values with `abc***xyz`
- **Block**: Reject critical-risk content entirely
- **Flag**: Surface high-risk content for manual review
- Configurable per-request via API options

---

## 🏗️ Architecture

```
Input (Text / File / SQL / Log / Chat)
         │
         ▼
    Validation Layer
         │
         ▼
    Extraction / Parser
         │
         ▼
    Detection Engine
    ├── Regex Patterns (14 categories)
    ├── AI Analysis (Claude claude-opus-4-5)
    └── Log Analyzer Module
         │
         ▼
    Risk Engine (score 0–100)
         │
         ▼
    Policy Engine (mask / block / flag)
         │
         ▼
    Structured JSON Response
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/)

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/ai-secure-platform.git
cd ai-secure-platform
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### 4. Start the Backend
```bash
uvicorn main:app --reload --port 8000
```

Backend runs at: `http://localhost:8000`  
API Docs: `http://localhost:8000/api/docs`

### 5. Open the Frontend
Simply open `frontend/index.html` in your browser.  
No build step required — it's pure HTML/CSS/JS.

---

## 📡 API Reference

### `POST /analyze` — Analyze any content

**Request:**
```json
{
  "input_type": "text | file | sql | chat | log",
  "content": "...",
  "options": {
    "mask": true,
    "block_high_risk": true,
    "log_analysis": true
  }
}
```

**Response:**
```json
{
  "request_id": "a3f91bc2",
  "timestamp": "2026-03-24T10:00:00Z",
  "input_type": "log",
  "summary": "Log contains sensitive credentials and system errors",
  "content_type": "logs",
  "findings": [
    {
      "type": "api_key",
      "risk": "high",
      "value": "sk-prod-xyz123",
      "masked_value": "sk-***123",
      "line": 12,
      "description": "API key or secret token detected"
    },
    {
      "type": "password",
      "risk": "critical",
      "value": "admin123",
      "masked_value": "adm***123",
      "line": 25,
      "description": "Password or credential exposed"
    }
  ],
  "risk_score": 85,
  "risk_level": "critical",
  "action": "blocked",
  "insights": [
    "Sensitive credentials exposed in logs",
    "Debug information leaked in stack traces",
    "💡 Rotate all exposed API keys immediately"
  ],
  "masked_content": "...masked version of input...",
  "processing_time_ms": 342,
  "policy_decision": {
    "action": "blocked",
    "blocked": true,
    "masked": true,
    "reason": "Critical risk content blocked by policy",
    "flagged_for_review": true
  }
}
```

### `POST /analyze/upload` — Upload file
```bash
curl -X POST http://localhost:8000/analyze/upload \
  -F "file=@app.log" \
  -F "mask=true" \
  -F "block_high_risk=true"
```

### `POST /analyze/chat` — Real-time chat scan
```bash
curl -X POST http://localhost:8000/analyze/chat \
  -F "message=my password is hunter2"
```

### `GET /patterns` — List all detection patterns
```bash
curl http://localhost:8000/patterns
```

### `GET /health` — Service health check
```bash
curl http://localhost:8000/health
```

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| Backend Framework | FastAPI (Python) |
| AI Engine | Anthropic Claude claude-opus-4-5 |
| Validation | Pydantic v2 |
| PDF Parsing | PyPDF2 |
| Pattern Detection | Python `re` module |
| Frontend | Vanilla HTML/CSS/JS |
| Server | Uvicorn (ASGI) |

---

## 📁 Project Structure

```
ai-secure-platform/
├── backend/
│   ├── main.py              # FastAPI app — all detection, AI, risk, policy logic
│   ├── requirements.txt     # Python dependencies
│   └── .env.example         # Environment variable template
├── frontend/
│   └── index.html           # Single-file frontend dashboard
└── README.md
```

---

## 🔒 Security Notes

- API keys are never stored — scanning is stateless
- All masking is done server-side before any response is returned
- AI analysis uses a sandboxed prompt — input content is never used for model training
- CORS is configurable for production deployment

---

## 🏆 Evaluation Criteria Coverage

| Category | Implementation |
|---|---|
| **Backend Design (18)** | FastAPI with layered architecture: validation → extraction → detection → risk → policy → response |
| **AI Integration (15)** | Claude claude-opus-4-5 for log summarization, anomaly detection, and contextual risk insights |
| **Multi-Input Handling (12)** | Text, file upload (PDF/TXT/LOG), SQL, chat, log — all via unified `/analyze` |
| **Log Analysis (15)** | Dedicated log analyzer module with line-level parsing, highlighting, and brute-force detection |
| **Detection + Risk Engine (12)** | 14 regex pattern categories + AI; aggregate risk scoring 0–100; 5 severity levels |
| **Policy Engine (8)** | Mask / block / flag / allow — configurable per request via options |
| **Frontend UI (10)** | Tabbed input, drag & drop, annotated log viewer, real-time risk meter, insights panel |
| **Security (5)** | Stateless, no storage, server-side masking, input validation, CORS |
| **Observability (3)** | Request IDs, timestamps, processing time, structured JSON logging |
| **Bonus (2)** | Drag & drop upload, annotated log viewer with line highlighting |

---

## 📽️ Demo

**Demo Video:** [YouTube / Drive Link]

The demo covers:
1. Pasting a log file with exposed credentials → see real-time detection
2. File upload with PDF → AI summarization
3. SQL injection detection
4. Policy engine blocking critical content

---

## 👤 Author

Built for the AI & Automation Testing Hackathon — March 2026.
