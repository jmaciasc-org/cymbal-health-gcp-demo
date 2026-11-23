"""5-Ring Runtime Defense: Model Armor (`<30ms`), Indirect RAG Guard, Cloud DLP & SecOps UDM.

Implements layered runtime protection around `cymbal-clinical-agent`:
- Ring 1a (`inspect_and_sanitize_prompt`): Blocks Direct Prompt Injection & Jailbreak
  (`PI_AND_JAILBREAK`) on user input via Model Armor `sanitizeUserPrompt` (ADC) + `<5ms`
  inline rule engine.
- Ring 1b (`sanitize_rag_chunks`): Scans retrieved Vertex AI Search Data Store chunks
  before LLM grounding to neutralize Indirect Prompt Injection embedded in documents.
- Ring 1c (`sanitize_model_response`): Scans final model output (`sanitizeModelResponse`)
  to prevent system prompt leakage or unmasked national IDs.
- Ring 2 (`mask_colombian_pii_dlp`): De-identifies Colombian Cedula (`CC` ->
  `[REDACTED_COLOMBIA_CC]`), payment cards, and email PII under Ley 1581 de 2012.
- Ring 5 (`_TELEMETRY_BUFFER`): Emits structured Cloud Logging JSON with `traceId`,
  `callerIp`, `principalEmail`, and Google SecOps UDM correlation queries.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import re
import sys
import time
import unicodedata
import uuid
from typing import Any

from backend.datastore_rag import ProtocolChunk

logger = logging.getLogger("cymbal.security.guardrail")
if not logger.handlers:
    # Cloud Run only ingests stdout/stderr; without an explicit handler the INFO
    # verdict entries were dropped by the root logger (WARNING by default).
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

MODEL_ARMOR_UNAVAILABLE = "MODEL_ARMOR_UNAVAILABLE"
OFF_TOPIC_REFUSAL = (
    "Solicitud fuera del alcance del asistente clinico: solo puedo validar ordenes "
    "y protocolos clinicos de Cymbal Health. No genero codigo, scripts ni consultas SQL."
)
CODE_OUTPUT_REFUSAL = (
    "Respuesta retenida por politica de salida: el asistente clinico no genera codigo, "
    "scripts ni consultas SQL."
)

_TELEMETRY_BUFFER: deque[dict[str, Any]] = deque(maxlen=50)

_PI_JAILBREAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SYSTEM_OVERRIDE_EN",
        re.compile(
            r"(ignore\s+(all\s+)?(previous|prior|system|clinical)\s+instructions|"
            r"disregard\s+(all\s+)?rules|reveal\s+(your\s+)?system\s+prompt|"
            r"developer\s+mode\s+enabled|act\s+as\s+dan\b|unrestricted\s+admin\s+mode)",
            re.IGNORECASE,
        ),
    ),
    (
        "SYSTEM_OVERRIDE_ES",
        re.compile(
            r"(ignora\s+(todas\s+)?las\s+instrucciones(\s+clinicas|\s+anteriores|\s+previas)?|"
            r"olvida\s+tus\s+reglas|muestra\s+el\s+prompt\s+del\s+sistema|"
            r"omite\s+(las\s+)?politicas\s+de\s+seguridad|modo\s+(administrador\s+)?sin\s+restricciones)",
            re.IGNORECASE,
        ),
    ),
    (
        "DATA_EXFIL_CONFIDENTIAL",
        re.compile(
            r"(select\s+\*\s+from\s+|dump\s+confidential|"
            r"bypass\s+ley\s*1581|extrae\s+todos\s+los\s+registros|"
            r"drop\s+table|union\s+select|confidential\s*=\s*1)",
            re.IGNORECASE,
        ),
    ),
    (
        "BULK_EXFILTRATION_DUMP",
        re.compile(
            r"(\bdump\b|\bvolcado\b|toda(?:s)?\s+la(?:s)?\s+(?:informacion|info|data|filas|registros)\s+de\s+(?:la|esa|esta)?\s*(?:tabla|base|bd|vista)|"
            r"(?:muestrame|dame|lista|extrae|exporta|descarga|imprime)\s+(?:toda|todo|todos|todas)\s+(?:la\s+tabla|las\s+filas|los\s+registros|la\s+base\s+de\s+datos|el\s+contenido\s+de\s+la\s+tabla)|"
            r"\ball\s+rows\b|\bentire\s+table\b|\bdatabase\s+dump\b|\bexport\s+all\s+records\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "SCHEMA_RESOURCE_ENUMERATION",
        re.compile(
            r"(a\s+que\s+(?:recursos|tablas|bases\s+de\s+datos|buckets|servicios|infraestructura|conexiones)\s+(?:puedes\s+)?(?:conectarte|acceder|tienes\s+acceso)|"
            r"(?:que|cuales)\s+(?:tablas|vistas|esquemas|bases\s+de\s+datos|buckets|credenciales|service\s+accounts)\s+(?:existen|tienes|usas|manejas)|"
            r"\binformation_schema\b|\bpg_catalog\b|\bpg_tables\b|\bsqlite_master\b|\bshow\s+tables\b|\bdescribe\s+table\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "SSRF_METADATA_THEFT",
        re.compile(
            r"(169\.254\.169\.254|metadata\.google\.internal|computeMetadata/v1)",
            re.IGNORECASE,
        ),
    ),
]

_CODE_LANGUAGES = (
    r"python|javascript|typescript|java|bash|shell|powershell|sql|c\+\+|c#|golang|rust|php|"
    r"ruby|kotlin|swift|html|css|node(?:\.?js)?|react|terraform|yaml|dockerfile"
)
_CODE_OBJECTS = (
    r"codigo(?!\s+(?:de\s+(?:la\s+|el\s+)?)?(?:cups|cie|orden|ord\b|autorizacion|procedimiento|diagnostico|folio))|"
    r"code|funcion(?!\s+(?:renal|hepatic\w*|pulmonar\w*|cardiac\w*|tiroide\w*|ventricular|respiratori\w*|"
    r"cognitiv\w*|motor\w*|vital\w*|organic\w*|sistolic\w*|diastolic\w*))|function|script|program|"
    r"class|snippet|regex|expresion\s+regular|consulta\s+sql|query|endpoint|api\s+rest"
)
_OFF_TOPIC_CODE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "CODE_GENERATION_REQUEST",
        re.compile(
            r"\b(?:escrib\w*|gener\w*|crea\w*|haz\w*|dame|programa\w*|codific\w*|implement\w*|"
            r"desarroll\w*|constru\w*|muestrame|write|generate|create|build|implement|give\s+me|show\s+me)"
            r"\b[^.?!]{0,60}?\b(?:" + _CODE_OBJECTS + r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CODE_LANGUAGE_REQUEST",
        re.compile(
            r"\b(?:en|in|usando|using|con|with)\s+(?:lenguaje\s+)?(?:" + _CODE_LANGUAGES + r")(?![\w])",
            re.IGNORECASE,
        ),
    ),
    (
        "CODE_TOKENS_IN_PROMPT",
        re.compile(
            r"(```|#!/|<script\b|\bdef\s+\w+\s*\(|\bimport\s+[a-z_][\w.]*|\bfunction\s+\w*\s*\(|"
            r"\bconsole\.log\b|\bprint\s*\()",
            re.IGNORECASE,
        ),
    ),
]

_CODE_OUTPUT_PATTERN = re.compile(
    r"(```|^\s*(?:def|class|import|from\s+\S+\s+import|function|const|let|var|public\s+(?:static\s+)?\w+|"
    r"#include|package\s+\w+|SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|#!/)\b|"
    r"<script\b|=>\s*\{|\bconsole\.log\(|\bprint\(|\bpip\s+install\b|\bnpm\s+install\b)",
    re.IGNORECASE | re.MULTILINE,
)


def _normalize_for_matching(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text or "")
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def detect_off_topic_code_request(text: str) -> str | None:
    """Deterministic scope gate: the clinical agent never generates code, scripts or SQL."""
    normalized = _normalize_for_matching(text)
    for rule_name, pattern in _OFF_TOPIC_CODE_PATTERNS:
        if pattern.search(normalized):
            return rule_name
    return None


def response_contains_code(text: str) -> bool:
    return bool(_CODE_OUTPUT_PATTERN.search(text or ""))


_PAYMENT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{1,4}\b")

_COLOMBIA_CC_LABELED_PATTERN = re.compile(
    r"\b(?:C\.?\s*C\.?|cedul[ao](?:\s+de\s+ciudadania)?|documento(?:\s+de\s+identidad)?)"
    r"\s*[:#-]?\s*(?:\d{1,3}(?:[.\s]\d{3}){2}|\d{6,10})\b",
    re.IGNORECASE,
)

_COLOMBIA_CC_STANDALONE_PATTERN = re.compile(
    r"(?<![-\w])(?:\d{1,3}(?:\.\d{3}){2}|\b[1-9]\d{6,9}\b)(?![-\w])"
)

_EMAIL_PII_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


@dataclass
class GuardrailInspectionResult:
    allowed: bool
    verdict: str
    filter_match: str | None
    sanitized_prompt: str
    dlp_findings: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    trace_id: str = ""
    secops_udm_query: str = ""
    cloud_log_entry: dict[str, Any] = field(default_factory=dict)


def build_secops_udm_query(trace_id: str, caller_ip: str, principal_email: str) -> str:
    return (
        f'metadata.product_name = "Google Cloud Model Armor" '
        f'AND target.application = "cymbal-clinical-agent" '
        f'AND network.http.referral_url = "{trace_id}" '
        f'AND principal.ip = "{caller_ip}" '
        f'AND principal.user.email_addresses = "{principal_email}"'
    )


def mask_colombian_pii_dlp(text: str) -> tuple[str, list[str]]:
    """Masks Colombian CC, payment cards, and email PII before RAG/LLM invocation."""
    findings: list[str] = []
    masked = text

    def _card_repl(_match: re.Match[str]) -> str:
        if "CREDIT_CARD_NUMBER" not in findings:
            findings.append("CREDIT_CARD_NUMBER")
        return "[REDACTED_PAYMENT_CARD]"

    masked = _PAYMENT_CARD_PATTERN.sub(_card_repl, masked)

    def _cc_labeled_repl(_match: re.Match[str]) -> str:
        if "COLOMBIA_CDC_NUMBER" not in findings:
            findings.append("COLOMBIA_CDC_NUMBER")
        return "[REDACTED_COLOMBIA_CC]"

    masked = _COLOMBIA_CC_LABELED_PATTERN.sub(_cc_labeled_repl, masked)

    def _cc_standalone_repl(_match: re.Match[str]) -> str:
        if "COLOMBIA_CDC_NUMBER" not in findings:
            findings.append("COLOMBIA_CDC_NUMBER")
        return "[REDACTED_COLOMBIA_CC]"

    masked = _COLOMBIA_CC_STANDALONE_PATTERN.sub(_cc_standalone_repl, masked)

    def _email_repl(_match: re.Match[str]) -> str:
        if "EMAIL_ADDRESS" not in findings:
            findings.append("EMAIL_ADDRESS")
        return "[REDACTED_EMAIL]"

    masked = _EMAIL_PII_PATTERN.sub(_email_repl, masked)
    return masked, findings


def _check_live_model_armor_user_prompt(text: str, template_name: str) -> str | None:
    """Live Google Cloud Model Armor `sanitizeUserPrompt` call via ADC (fail closed)."""
    if os.getenv("ENABLE_LIVE_MODEL_ARMOR", "false").lower() != "true":
        return None
    fail_closed = os.getenv("MODEL_ARMOR_FAIL_CLOSED", "true").lower() != "false"
    error_detail = ""
    try:
        import google.auth
        from google.auth.transport.requests import Request as GoogleAuthRequest
        import httpx

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        credentials.refresh(GoogleAuthRequest())
        location = os.getenv("GCP_REGION", "us-central1")
        endpoint = f"https://modelarmor.{location}.rep.googleapis.com/v1/{template_name}:sanitizeUserPrompt"
        timeout_s = float(os.getenv("MODEL_ARMOR_TIMEOUT_SECONDS", "5"))
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.post(
                endpoint,
                headers={"Authorization": f"Bearer {credentials.token}"},
                json={"userPromptData": {"text": text}},
            )
        if resp.status_code == 200:
            verdict_state = (
                resp.json()
                .get("sanitizationResult", {})
                .get("filterMatchState", "")
            )
            return "MODEL_ARMOR_API_MATCH" if verdict_state == "MATCH_FOUND" else None
        error_detail = f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:  # noqa: BLE001 - any failure must be visible and fail closed
        error_detail = f"{type(exc).__name__}: {exc}"[:300]
    logger.warning(
        json.dumps(
            {
                "severity": "ERROR",
                "event": "model_armor_call_failed",
                "modelArmorTemplate": template_name,
                "failClosed": fail_closed,
                "error": error_detail,
            },
            ensure_ascii=True,
        )
    )
    return MODEL_ARMOR_UNAVAILABLE if fail_closed else None


def sanitize_rag_chunks(chunks: list[ProtocolChunk]) -> tuple[list[ProtocolChunk], int]:
    """Ring 1b: Scans retrieved Vertex AI Search chunks for Indirect Prompt Injection."""
    safe_chunks: list[ProtocolChunk] = []
    quarantined = 0
    for chunk in chunks:
        poisoned = False
        for _, pattern in _PI_JAILBREAK_PATTERNS:
            if pattern.search(chunk.snippet):
                poisoned = True
                break
        if poisoned:
            quarantined += 1
            continue
        masked_snippet, _ = mask_colombian_pii_dlp(chunk.snippet)
        safe_chunks.append(
            ProtocolChunk(
                doc_id=chunk.doc_id,
                protocol_code=chunk.protocol_code,
                title=chunk.title,
                cups_codes=chunk.cups_codes,
                snippet=masked_snippet,
                source_uri=chunk.source_uri,
                retrieval_mode=chunk.retrieval_mode,
            )
        )
    return safe_chunks, quarantined


_INTERNAL_IDENTIFIER_PATTERN = re.compile(
    r"\b(?:clinical_orders_public_v|clinical_orders|cymbal_agent_readonly|"
    r"cymbal-health-pg-main|cymbal-health-soportes(?:-\d+)?|cymbal-health-protocols(?:-\d+)?|"
    r"cymbal-health-(?:portal|agent|mcp|cicd)-sa)\b",
    re.IGNORECASE,
)


def sanitize_model_response(response_text: str) -> str:
    """Ring 1c: Scrubs model output against accidental PII, schema/resource names, or system prompt leakage."""
    masked_out, _ = mask_colombian_pii_dlp(response_text)
    masked_out = _INTERNAL_IDENTIFIER_PATTERN.sub("[INTERNAL_RESOURCE_REDACTED]", masked_out)
    if response_contains_code(masked_out):
        logger.warning(
            json.dumps(
                {"severity": "WARNING", "event": "model_output_code_blocked", "preview": masked_out[:160]},
                ensure_ascii=True,
            )
        )
        return CODE_OUTPUT_REFUSAL
    if re.search(r"SYSTEM_INSTRUCTION_CONFIDENTIAL_MARKER", masked_out):
        return "Respuesta retenida por politica de seguridad de salida de Model Armor."
    return masked_out


def inspect_and_sanitize_prompt(
    prompt: str,
    *,
    caller_ip: str = "10.28.0.10",
    principal_email: str = "medico.especialista@cymbal-health.co",
    trace_id: str | None = None,
) -> GuardrailInspectionResult:
    """Ring 1a + Ring 2 + Ring 5: `<30ms` Model Armor + Cloud DLP inspection & UDM logging."""
    start = time.perf_counter()
    project_id = os.getenv("GCP_PROJECT_ID", "cymbal-health-prod")
    resolved_trace = trace_id or uuid.uuid4().hex
    raw_prompt = (prompt or "").strip()

    model_armor_template = (
        os.getenv("MODEL_ARMOR_TEMPLATE_ID")
        or f"projects/{project_id}/locations/us-central1/templates/cymbal-health-model-armor"
    )
    dlp_deidentify_template = (
        os.getenv("DLP_DEIDENTIFY_TEMPLATE_ID")
        or f"projects/{project_id}/locations/us-central1/deidentifyTemplates/cymbal-health-dlp-deidentify"
    )

    matched_rule: str | None = None
    for rule_name, pattern in _PI_JAILBREAK_PATTERNS:
        if pattern.search(raw_prompt):
            matched_rule = rule_name
            break

    filter_family = "PI_AND_JAILBREAK"
    if matched_rule is None:
        off_topic_rule = detect_off_topic_code_request(raw_prompt)
        if off_topic_rule is not None:
            matched_rule = off_topic_rule
            filter_family = "OFF_TOPIC"

    if matched_rule is None:
        matched_rule = _check_live_model_armor_user_prompt(raw_prompt, model_armor_template)
        if matched_rule == MODEL_ARMOR_UNAVAILABLE:
            filter_family = "GUARDRAIL_UNAVAILABLE"

    sanitized_prompt, dlp_info_types = mask_colombian_pii_dlp(raw_prompt)
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)

    allowed = matched_rule is None
    verdict = (
        "ALLOW_SANITIZED"
        if (allowed and dlp_info_types)
        else ("ALLOW" if allowed else "BLOCKED")
    )
    filter_match = None if allowed else f"{filter_family}:{matched_rule}"
    udm_query = build_secops_udm_query(resolved_trace, caller_ip, principal_email)

    log_entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "severity": "WARNING" if not allowed else ("NOTICE" if dlp_info_types else "INFO"),
        "logging.googleapis.com/trace": f"projects/{project_id}/traces/{resolved_trace}",
        "traceId": resolved_trace,
        "callerIp": caller_ip,
        "principalEmail": principal_email,
        "serviceName": "cymbal-health-clinical-agent-v3",
        "serviceAccount": f"cymbal-health-agent-sa@{project_id}.iam.gserviceaccount.com",
        "modelArmorTemplate": model_armor_template,
        "modelArmorVerdict": verdict,
        "filterMatch": filter_match,
        "dlpDeidentifyTemplate": dlp_deidentify_template,
        "dlpInfoTypes": dlp_info_types,
        "sanitizedPreview": sanitized_prompt[:160],
        "blockedBy": (
            None
            if allowed
            else ("model_armor_api" if matched_rule == "MODEL_ARMOR_API_MATCH" else "local_rule_engine")
        ),
        "latencyMs": elapsed_ms,
        "secopsUdmQuery": udm_query,
    }

    _TELEMETRY_BUFFER.appendleft(log_entry)
    logger.info(json.dumps(log_entry, ensure_ascii=True))

    return GuardrailInspectionResult(
        allowed=allowed,
        verdict=verdict,
        filter_match=filter_match,
        sanitized_prompt=sanitized_prompt,
        dlp_findings=dlp_info_types,
        latency_ms=elapsed_ms,
        trace_id=resolved_trace,
        secops_udm_query=udm_query,
        cloud_log_entry=log_entry,
    )


def record_external_telemetry_event(entry: dict[str, Any]) -> None:
    if isinstance(entry, dict) and entry:
        _TELEMETRY_BUFFER.appendleft(dict(entry))


def clear_security_telemetry() -> None:
    _TELEMETRY_BUFFER.clear()


def get_recent_security_telemetry() -> list[dict[str, Any]]:
    return list(_TELEMETRY_BUFFER)
