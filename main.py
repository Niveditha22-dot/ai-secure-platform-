"""
AI Secure Data Intelligence Platform
FastAPI Backend - AI Gateway + Scanner + Log Analyzer + Risk Engine
"""

import os
import re
import json
import time
import hashlib
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

import anthropic
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import PyPDF2
import io

# ─────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description="AI Gateway + Scanner + Log Analyzer + Risk Engine",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Anthropic Client
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

# ─────────────────────────────────────────
# Enums & Models
# ─────────────────────────────────────────

class InputType(str, Enum):
    TEXT = "text"
    FILE = "file"
    SQL = "sql"
    CHAT = "chat"
    LOG = "log"

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"

class AnalyzeRequest(BaseModel):
    input_type: InputType
    content: str
    options: Optional[Dict[str, Any]] = Field(default_factory=lambda: {
        "mask": True,
        "block_high_risk": True,
        "log_analysis": True
    })

class Finding(BaseModel):
    type: str
    risk: str
    value: str
    masked_value: Optional[str] = None
    line: Optional[int] = None
    description: str

class AnalyzeResponse(BaseModel):
    request_id: str
    timestamp: str
    input_type: str
    summary: str
    content_type: str
    findings: List[Finding]
    risk_score: int
    risk_level: str
    action: str
    insights: List[str]
    masked_content: Optional[str] = None
    processing_time_ms: int
    policy_decision: Dict[str, Any]

# ─────────────────────────────────────────
# Detection Patterns
# ─────────────────────────────────────────

DETECTION_PATTERNS = {
    "api_key": {
        "patterns": [
            r'(?i)(api[_-]?key|apikey)["\s:=]+([A-Za-z0-9\-_]{20,})',
            r'(?i)sk-[A-Za-z0-9]{32,}',
            r'(?i)(bearer\s+)([A-Za-z0-9\-_.]{20,})',
            r'(?i)AKIA[0-9A-Z]{16}',  # AWS
            r'(?i)AIza[0-9A-Za-z\-_]{35}',  # Google
        ],
        "risk": RiskLevel.HIGH,
        "description": "API key or secret token detected"
    },
    "password": {
        "patterns": [
            r'(?i)(password|passwd|pwd)["\s:=]+([^\s"\']{4,})',
            r'(?i)(secret)["\s:=]+([^\s"\']{4,})',
            r'(?i)(credentials)["\s:=]+([^\s"\']{4,})',
        ],
        "risk": RiskLevel.CRITICAL,
        "description": "Password or credential exposed"
    },
    "email": {
        "patterns": [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        "risk": RiskLevel.LOW,
        "description": "Email address found"
    },
    "phone": {
        "patterns": [
            r'(?<!\d)(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})(?!\d)',
        ],
        "risk": RiskLevel.LOW,
        "description": "Phone number detected"
    },
    "token": {
        "patterns": [
            r'(?i)(token|access_token|auth_token)["\s:=]+([A-Za-z0-9\-_.]{20,})',
            r'(?i)ghp_[A-Za-z0-9]{36}',  # GitHub PAT
            r'(?i)xoxb-[0-9]{11}-[A-Za-z0-9]{24}',  # Slack token
        ],
        "risk": RiskLevel.HIGH,
        "description": "Authentication token exposed"
    },
    "private_key": {
        "patterns": [
            r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        ],
        "risk": RiskLevel.CRITICAL,
        "description": "Private key material detected"
    },
    "sql_injection": {
        "patterns": [
            r'(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into|exec\s*\(|xp_cmdshell)',
            r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s+or\s+')",
        ],
        "risk": RiskLevel.CRITICAL,
        "description": "SQL injection pattern detected"
    },
    "ip_address": {
        "patterns": [
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        ],
        "risk": RiskLevel.MEDIUM,
        "description": "Internal IP address exposed"
    },
    "stack_trace": {
        "patterns": [
            r'(?i)(traceback|stack trace|exception in thread|at .+\.java:\d+)',
            r'(?i)(NullPointerException|IndexOutOfBoundsException|SQLException)',
        ],
        "risk": RiskLevel.MEDIUM,
        "description": "Stack trace or error leak detected"
    },
    "connection_string": {
        "patterns": [
            r'(?i)(mongodb|mysql|postgresql|redis):\/\/[^\s]+',
            r'(?i)(server|host)=[^;]+;.*(database|catalog)=[^;]+;.*(uid|user)=[^;]+',
        ],
        "risk": RiskLevel.CRITICAL,
        "description": "Database connection string exposed"
    },
}

RISK_SCORES = {
    RiskLevel.CRITICAL: 40,
    RiskLevel.HIGH: 25,
    RiskLevel.MEDIUM: 10,
    RiskLevel.LOW: 3,
    RiskLevel.SAFE: 0,
}

# ─────────────────────────────────────────
# Detection Engine
# ─────────────────────────────────────────

def mask_value(value: str) -> str:
    """Mask sensitive values, showing only first/last 3 chars."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def run_detection(content: str) -> List[Finding]:
    """Run all regex detection patterns against content."""
    findings = []
    lines = content.split("\n")
    seen = set()

    for pattern_type, config in DETECTION_PATTERNS.items():
        for pattern in config["patterns"]:
            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line)
                for match in matches:
                    raw = match.group(0)
                    # Deduplicate
                    key = f"{pattern_type}:{raw}"
                    if key in seen:
                        continue
                    seen.add(key)

                    masked = mask_value(raw)
                    findings.append(Finding(
                        type=pattern_type,
                        risk=config["risk"].value,
                        value=raw,
                        masked_value=masked,
                        line=line_num,
                        description=config["description"],
                    ))
    return findings


def calculate_risk(findings: List[Finding]) -> tuple[int, RiskLevel]:
    """Calculate aggregate risk score and level from findings."""
    score = 0
    for f in findings:
        level = RiskLevel(f.risk)
        score += RISK_SCORES.get(level, 0)

    score = min(score, 100)

    if score >= 70:
        level = RiskLevel.CRITICAL
    elif score >= 40:
        level = RiskLevel.HIGH
    elif score >= 20:
        level = RiskLevel.MEDIUM
    elif score > 0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.SAFE

    return score, level


def apply_masking(content: str, findings: List[Finding]) -> str:
    """Apply masking to all sensitive values in content."""
    masked = content
    # Sort by length descending to avoid partial replacements
    sorted_findings = sorted(findings, key=lambda f: len(f.value), reverse=True)
    for f in sorted_findings:
        if f.masked_value:
            masked = masked.replace(f.value, f.masked_value)
    return masked


def apply_policy(risk_score: int, risk_level: RiskLevel, options: Dict) -> Dict:
    """Apply policy engine decisions."""
    block_high_risk = options.get("block_high_risk", True)
    mask = options.get("mask", True)

    action = "allowed"
    blocked = False
    reason = "Content passed all security checks"

    if risk_level == RiskLevel.CRITICAL and block_high_risk:
        action = "blocked"
        blocked = True
        reason = "Critical risk content blocked by policy"
    elif risk_level == RiskLevel.HIGH and block_high_risk:
        action = "masked_and_flagged"
        reason = "High risk content masked and flagged for review"
    elif mask and risk_level not in [RiskLevel.SAFE]:
        action = "masked"
        reason = "Sensitive content masked per policy"

    return {
        "action": action,
        "blocked": blocked,
        "masked": mask and risk_level != RiskLevel.SAFE,
        "reason": reason,
        "flagged_for_review": risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
    }


def detect_content_type(content: str, input_type: InputType) -> str:
    """Infer content type from input."""
    if input_type == InputType.LOG:
        return "logs"
    if input_type == InputType.SQL:
        return "sql"
    if re.search(r'\d{4}-\d{2}-\d{2}.*(INFO|ERROR|WARN|DEBUG)', content, re.IGNORECASE):
        return "logs"
    if re.search(r'SELECT|INSERT|UPDATE|DELETE|FROM|WHERE', content, re.IGNORECASE):
        return "sql"
    return "text"

# ─────────────────────────────────────────
# AI Analysis Engine
# ─────────────────────────────────────────

def build_ai_prompt(content: str, findings: List[Finding], content_type: str, options: Dict) -> str:
    findings_summary = "\n".join([
        f"- Line {f.line}: [{f.risk.upper()}] {f.type} — {f.description}"
        for f in findings[:20]
    ])
    if not findings_summary:
        findings_summary = "No specific patterns detected by regex engine."

    return f"""You are an expert cybersecurity analyst and data security auditor. Analyze the following {content_type} content for security risks, data leaks, and anomalies.

CONTENT TYPE: {content_type}
OPTIONS: {json.dumps(options)}

CONTENT (first 3000 chars):
{content[:3000]}

REGEX ENGINE FINDINGS:
{findings_summary}

Provide your analysis in the following JSON format ONLY (no markdown, no explanation outside JSON):
{{
  "summary": "One sentence executive summary of what was found",
  "insights": ["insight1", "insight2", "insight3"],
  "anomalies": ["anomaly1"],
  "additional_risks": [
    {{"type": "risk_type", "risk": "high|medium|low|critical", "description": "what was found", "line": null}}
  ],
  "recommendations": ["action1", "action2"]
}}

Rules:
- insights: 3-5 actionable security observations
- anomalies: patterns that look suspicious (brute force, repeated failures, debug leaks)
- additional_risks: risks the regex engine may have missed (behavioral, contextual)
- Be specific and technical. Reference actual content found."""


def call_claude(prompt: str) -> Dict:
    """Call Claude API for AI analysis."""
    try:
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.content[0].text.strip()
        # Strip potential markdown fences
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning(f"Claude returned non-JSON: {e}")
        return {
            "summary": "AI analysis completed with partial results.",
            "insights": ["Manual review recommended for full analysis."],
            "anomalies": [],
            "additional_risks": [],
            "recommendations": ["Review flagged findings manually."]
        }
    except Exception as e:
        logger.error(f"Claude API error: {e}")
        return {
            "summary": "AI analysis unavailable. Regex engine results only.",
            "insights": ["Configure ANTHROPIC_API_KEY for AI-powered insights."],
            "anomalies": [],
            "additional_risks": [],
            "recommendations": []
        }

# ─────────────────────────────────────────
# Core Analysis Orchestrator
# ─────────────────────────────────────────

def analyze_content(content: str, input_type: InputType, options: Dict) -> AnalyzeResponse:
    start_time = time.time()
    request_id = hashlib.md5(f"{content[:100]}{time.time()}".encode()).hexdigest()[:12]

    # 1. Detect content type
    content_type = detect_content_type(content, input_type)

    # 2. Run regex detection
    findings = run_detection(content)

    # 3. Risk scoring
    risk_score, risk_level = calculate_risk(findings)

    # 4. AI analysis
    ai_result = {}
    if options.get("log_analysis", True) or len(content) > 50:
        prompt = build_ai_prompt(content, findings, content_type, options)
        ai_result = call_claude(prompt)

        # Merge additional AI-detected risks
        for ar in ai_result.get("additional_risks", []):
            findings.append(Finding(
                type=ar.get("type", "ai_detected"),
                risk=ar.get("risk", "medium"),
                value="[AI Detected]",
                masked_value=None,
                line=ar.get("line"),
                description=ar.get("description", "AI-identified risk")
            ))

        # Recalculate after AI additions
        risk_score, risk_level = calculate_risk(findings)

    # 5. Apply policy
    policy = apply_policy(risk_score, risk_level, options)

    # 6. Masking
    masked_content = None
    if options.get("mask", True) and findings:
        masked_content = apply_masking(content, findings)

    # 7. Build final response
    action = policy["action"]
    summary = ai_result.get("summary", f"Analysis complete. {len(findings)} findings detected.")
    insights = ai_result.get("insights", [])
    if ai_result.get("anomalies"):
        insights += [f"⚠️ Anomaly: {a}" for a in ai_result["anomalies"]]
    if ai_result.get("recommendations"):
        insights += [f"💡 {r}" for r in ai_result["recommendations"]]

    elapsed_ms = int((time.time() - start_time) * 1000)

    return AnalyzeResponse(
        request_id=request_id,
        timestamp=datetime.utcnow().isoformat() + "Z",
        input_type=input_type.value,
        summary=summary,
        content_type=content_type,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level.value,
        action=action,
        insights=insights,
        masked_content=masked_content,
        processing_time_ms=elapsed_ms,
        policy_decision=policy,
    )

# ─────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AI Secure Data Intelligence Platform",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    """
    Analyze text/SQL/chat/log content for security risks.
    """
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    result = analyze_content(
        content=request.content,
        input_type=request.input_type,
        options=request.options or {}
    )
    return result


@app.post("/analyze/upload", response_model=AnalyzeResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    mask: bool = Form(True),
    block_high_risk: bool = Form(True),
    log_analysis: bool = Form(True),
):
    """
    Analyze uploaded file (PDF, TXT, LOG, DOC).
    """
    filename = file.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"

    raw_bytes = await file.read()

    # Extract text based on file type
    try:
        if ext == "pdf":
            reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
            content = "\n".join(
                page.extract_text() or "" for page in reader.pages
            )
            input_type = InputType.FILE
        elif ext in ("log",):
            content = raw_bytes.decode("utf-8", errors="replace")
            input_type = InputType.LOG
        else:
            content = raw_bytes.decode("utf-8", errors="replace")
            input_type = InputType.FILE
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Could not parse file: {e}")

    if not content.strip():
        raise HTTPException(status_code=400, detail="File appears to be empty or unreadable")

    options = {"mask": mask, "block_high_risk": block_high_risk, "log_analysis": log_analysis}
    result = analyze_content(content=content, input_type=input_type, options=options)
    return result


@app.post("/analyze/chat")
async def analyze_chat(message: str = Form(...)):
    """
    Analyze a live chat message for sensitive content before delivery.
    """
    result = analyze_content(
        content=message,
        input_type=InputType.CHAT,
        options={"mask": True, "block_high_risk": True, "log_analysis": False}
    )
    safe_message = result.masked_content if result.masked_content else message
    return {
        "original": message,
        "safe_message": safe_message,
        "risk_level": result.risk_level,
        "action": result.action,
        "findings_count": len(result.findings),
    }


@app.get("/patterns")
def get_patterns():
    """List all detection patterns and their risk levels."""
    return {
        name: {
            "risk": config["risk"].value,
            "description": config["description"],
            "pattern_count": len(config["patterns"])
        }
        for name, config in DETECTION_PATTERNS.items()
    }


@app.get("/")
def root():
    return {
        "message": "AI Secure Data Intelligence Platform",
        "docs": "/api/docs",
        "health": "/health",
        "endpoints": ["/analyze", "/analyze/upload", "/analyze/chat", "/patterns"]
    }
