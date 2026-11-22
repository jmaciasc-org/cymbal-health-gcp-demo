"""Test suite for pure Cymbal Health v1.0 baseline (`main` branch)."""

from __future__ import annotations

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path[:] = [
    p
    for p in sys.path
    if not (p == "" and (Path.cwd() / "calendar" / "__init__.py").exists())
]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient
import pytest

from backend.app import app
from backend.db import reset_database

EMOJI_REGEX = re.compile(
    "["
    "\U0001F1E0-\U0001F1FF"
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F700-\U0001F77F"
    "\U0001F780-\U0001F7FF"
    "\U0001F800-\U0001F8FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA00-\U0001FAFF"
    "\u2600-\u27BF"
    "\uFE0F"
    "]"
)


@pytest.fixture(autouse=True)
def _reset_db() -> None:
    reset_database()


def test_zero_emojis_across_repository() -> None:
    binary_exts = {
        ".png",
        ".jpg",
        ".jpeg",
        ".pdf",
        ".zip",
        ".ico",
        ".woff",
        ".woff2",
        ".so",
        ".pyc",
        ".pyo",
        ".whl",
    }
    text_files = [
        p
        for p in REPO_ROOT.rglob("*")
        if p.is_file()
        and ".git" not in p.parts
        and ".venv" not in p.parts
        and "venv" not in p.parts
        and ".terraform" not in p.parts
        and "__pycache__" not in p.parts
        and ".pytest_cache" not in p.parts
        and p.suffix.lower() not in binary_exts
    ]
    assert len(text_files) >= 12
    for file_path in text_files:
        text = file_path.read_text(encoding="utf-8")
        assert not EMOJI_REGEX.search(text), f"Emoji found in {file_path}"


def test_pure_v1_has_no_agent_endpoints_or_demo_buttons() -> None:
    client = TestClient(app)
    root_resp = client.get("/")
    html = root_resp.text
    assert root_resp.status_code == 200
    assert "no-store" in root_resp.headers.get("cache-control", "")
    assert re.search(r'href="/styles\.css\?v=[0-9a-f]{12}"', html)
    assert re.search(r'src="/app\.js\?v=[0-9a-f]{12}"', html)

    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "no-store" in js_resp.headers.get("cache-control", "")

    css_resp = client.get("/styles.css")
    assert css_resp.status_code == 200
    assert "no-store" in css_resp.headers.get("cache-control", "")

    assert "Cymbal Health | Autorizaciones Clinicas" in html
    assert "modal-clinical-agent" not in html
    assert "btn-open-clinical-agent" not in html
    assert "btn-open-telemetry" not in html
    assert "v1.0 Base" not in html
    assert "Model Armor" not in html

    # Pre-filled order values present out-of-the-box for 1-click submission
    assert 'value="P. Cardenas Montoya"' in html
    assert 'value="895001"' in html
    assert "Monitoreo Electrocardiografico Continuo Holter 24 Horas" in html

    assert client.get("/api/agent/card").status_code == 404
    assert client.post("/api/agent/assist", json={"prompt": "test"}).status_code == 404


def test_orders_workflow_sqli_protection_and_hospital_pdf() -> None:
    client = TestClient(app)

    orders = client.get("/api/orders").json()
    assert orders["count"] == 5
    assert orders["kpis"]["authorized_count"] == orders["kpis"]["authorized_today"] == 3
    assert orders["kpis"]["pending_count"] == orders["kpis"]["pending_signature"] == 2
    codes = {o["order_code"] for o in orders["items"]}
    assert "ORD-2026-1041" in codes
    assert "ORD-2026-9901" not in codes

    # Parameterized search blocks SQL injection
    sqli = client.get("/api/orders/search", params={"q": "' OR '1'='1 --"}).json()
    assert sqli["count"] == 0

    # Create order using pre-filled defaults
    defaults = client.get("/api/orders/defaults").json()
    created_resp = client.post("/api/orders", json=defaults)
    assert created_resp.status_code == 201
    created = created_resp.json()["item"]
    assert created["document_masked"] == "CC ***9120"
    assert created["cups_code"] == "895001"

    # Hospital-grade PDF check (zero cloud bucket URI jargon)
    pdf_resp = client.get("/api/orders/ORD-2026-1041/support.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    raw = pdf_resp.content
    assert raw.startswith(b"%PDF-1.4")
    assert b"CYMBAL HEALTH IPS - RED DE DIAGNOSTICO ESPECIALIZADO" in raw
    assert b"881234" in raw
    assert b"I10X" in raw
    assert b"re B" in raw
    assert b"gs://" not in raw


def test_readiness_probe_reports_database_backend() -> None:
    client = TestClient(app)
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["database"]["connected"] is True
    assert body["database"]["engine"] == "sqlite-local-mirror"
    assert body["database"]["static_password_configured"] is False
