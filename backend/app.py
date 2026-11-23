"""FastAPI Web Portal Backend for Cymbal Health (v1.0 Production Baseline)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import APP_NAME, APP_SERVICE_PORTAL, APP_VERSION
from backend.db import (
    check_database_connection,
    create_clinical_order,
    get_public_order,
    list_public_orders,
    search_orders,
)
from backend.eps_sync import export_orders_for_eps
from backend.seed_data import DEFAULT_PREFILLED_ORDER
from backend.storage_client import (
    fetch_order_support_pdf,
    get_supports_bucket_name,
    upload_order_support_pdf,
)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


def _compute_asset_version() -> str:
    digest = hashlib.sha256()
    for fname in ("index.html", "styles.css", "app.js"):
        fpath = FRONTEND_DIR / fname
        if fpath.is_file():
            digest.update(fpath.read_bytes())
    return digest.hexdigest()[:12]


_ASSET_VER = _compute_asset_version()


class CreateOrderPayload(BaseModel):
    patient_alias: str = Field(..., min_length=2, max_length=80)
    document_masked: str = Field(..., min_length=4, max_length=32)
    eps_name: str = Field(default="EPS Sanitas - Contributivo", min_length=3, max_length=80)
    specialty: str = Field(..., min_length=3, max_length=60)
    cups_code: str = Field(default="895001", min_length=4, max_length=12)
    cie10_code: str = Field(
        default="I499 - Arritmia cardiaca en estudio", min_length=3, max_length=90
    )
    procedure_name: str = Field(..., min_length=4, max_length=140)
    center_city: str = Field(..., min_length=3, max_length=40)
    attending_physician: str = Field(
        default="Dra. Natalia Gomez Arango (RM 110492810)", min_length=5, max_length=90
    )
    priority: Literal["ALTA", "MEDIA", "BAJA"] = "ALTA"
    clinical_summary: str = Field(..., min_length=5, max_length=420)
    patient_preparation: str | None = Field(default=None, max_length=420)


app = FastAPI(
    title="Cymbal Health - Autorizaciones Clinicas",
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url=None,
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Any) -> Response:
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    path = request.url.path
    if (
        path in ("/", "/app.js", "/styles.css")
        or path.startswith("/api/")
        or path.startswith("/static/")
    ):
        for hdr_key, hdr_val in NO_CACHE_HEADERS.items():
            response.headers[hdr_key] = hdr_val
    return response


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "application": APP_NAME,
        "service": APP_SERVICE_PORTAL,
        "version": APP_VERSION,
        "asset_version": _ASSET_VER,
    }


@app.get("/readyz")
def readyz(response: Response) -> dict[str, Any]:
    """Readiness probe: verifies the database connection (Cloud SQL over private IP with IAM auth)."""
    database = check_database_connection()
    connected = bool(database.get("connected"))
    if not connected:
        response.status_code = 503
    response.headers.update(NO_CACHE_HEADERS)
    # Public response is intentionally minimal; instance, principal and errors go to Cloud Logging only.
    return {"status": "ready" if connected else "not_ready", "database": {"engine": database["engine"], "connected": connected}}


@app.get("/api/eps/export")
def api_export_eps_orders(eps: str = Query(default="Sanitas", max_length=200)) -> dict[str, Any]:
    items = export_orders_for_eps(eps)
    return {"eps": eps, "count": len(items), "items": items}


@app.get("/api/orders/defaults")
def api_order_defaults() -> dict[str, str]:
    return dict(DEFAULT_PREFILLED_ORDER)


@app.get("/api/orders")
def api_list_orders(status: str | None = Query(default=None, max_length=30)) -> dict[str, Any]:
    items = list_public_orders(status_filter=status)
    all_items = list_public_orders() if status else items
    authorized_count = sum(1 for o in all_items if o["status"] == "AUTORIZADA")
    pending_count = sum(
        1 for o in all_items if o["status"] in ("PENDIENTE_FIRMA", "EN_REVISION")
    )
    cities = sorted({o["center_city"] for o in all_items})
    return {
        "items": items,
        "count": len(items),
        "kpis": {
            "active_orders": len(all_items),
            "authorized_count": authorized_count,
            "authorized_today": authorized_count,
            "pending_count": pending_count,
            "pending_signature": pending_count,
            "regional_centers": f"{len(cities)} sedes",
        },
    }


@app.get("/api/orders/search")
def api_search_orders(q: str = Query(default="", max_length=200)) -> dict[str, Any]:
    return search_orders(q)


@app.post("/api/orders", status_code=201)
def api_create_order(payload: CreateOrderPayload) -> dict[str, Any]:
    raw_doc = payload.document_masked.strip()
    digits_only = "".join(ch for ch in raw_doc if ch.isdigit())
    if digits_only and len(digits_only) >= 6 and "*" not in raw_doc:
        masked_doc = f"CC ***{digits_only[-4:]}"
    else:
        masked_doc = raw_doc

    created = create_clinical_order(
        patient_alias=payload.patient_alias,
        document_masked=masked_doc,
        eps_name=payload.eps_name,
        specialty=payload.specialty,
        cups_code=payload.cups_code,
        cie10_code=payload.cie10_code,
        procedure_name=payload.procedure_name,
        center_city=payload.center_city,
        attending_physician=payload.attending_physician,
        priority=payload.priority,
        clinical_summary=payload.clinical_summary,
        patient_preparation=payload.patient_preparation,
    )
    storage_sync = upload_order_support_pdf(created)
    return {"item": created, "storage": storage_sync}


@app.get("/api/orders/{order_code}")
def api_get_order_detail(order_code: str) -> dict[str, Any]:
    order = get_public_order(order_code)
    if not order:
        raise HTTPException(status_code=404, detail="Orden clinica no encontrada.")
    return {
        "item": order,
        "support_pdf_url": f"/api/orders/{order['order_code']}/support.pdf?v={_ASSET_VER}",
        "storage": {
            "bucket": get_supports_bucket_name(),
            "object": order["support_pdf_object"],
        },
    }


@app.get("/api/orders/{order_code}/support.pdf")
def api_download_order_pdf(order_code: str) -> Response:
    order = get_public_order(order_code)
    if not order:
        raise HTTPException(status_code=404, detail="Soporte PDF no encontrado.")
    pdf_bytes = fetch_order_support_pdf(order)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{order["order_code"]}-autorizacion.pdf"',
            **NO_CACHE_HEADERS,
        },
    )


@app.get("/", response_class=HTMLResponse)
def serve_portal_ui() -> Response:
    index_file = FRONTEND_DIR / "index.html"
    html = (
        index_file.read_text(encoding="utf-8")
        .replace('href="/styles.css"', f'href="/styles.css?v={_ASSET_VER}"')
        .replace('src="/app.js"', f'src="/app.js?v={_ASSET_VER}"')
    )
    return HTMLResponse(content=html, status_code=200, headers=dict(NO_CACHE_HEADERS))


@app.get("/styles.css")
def serve_css() -> Response:
    css_text = (FRONTEND_DIR / "styles.css").read_text(encoding="utf-8")
    return Response(
        content=css_text,
        media_type="text/css; charset=utf-8",
        headers=dict(NO_CACHE_HEADERS),
    )


@app.get("/app.js")
def serve_js() -> Response:
    js_text = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    return Response(
        content=js_text,
        media_type="application/javascript; charset=utf-8",
        headers=dict(NO_CACHE_HEADERS),
    )
