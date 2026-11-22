"""Database access layer for the Cymbal Health v1.0 Clinical Authorizations Portal.

Production (Cloud Run): Cloud SQL for PostgreSQL 15 over private IP, authenticated
with IAM database authentication through the Cloud SQL Python Connector. The
connector obtains short-lived OAuth2 tokens from Application Default Credentials,
so there are no database passwords in code, images or environment variables.
Connections are pooled with SQLAlchemy.

Local development and CI: an in-memory SQLite database with the same schema and
seed data, selected automatically when DB_INSTANCE_CONNECTION_NAME is not set
(or explicitly with DB_BACKEND=sqlite).

Schema, roles and seed data in Cloud SQL are owned by versioned migrations in
db/migrations/, never created by the application at runtime (the runtime
identity has no DDL privileges).
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import sqlalchemy
from sqlalchemy import text
from sqlalchemy.pool import StaticPool

from backend.seed_data import DEFAULT_PREFILLED_ORDER, SEED_CLINICAL_ORDERS

logger = logging.getLogger("cymbal.db")

COLOMBIA_TZ = timezone(timedelta(hours=-5), name="COT")
ORDER_CODE_FIRST_NUMBER = 1041

_ENGINE_LOCK = threading.Lock()
_SQLITE_LOCK = threading.RLock()
_ENGINE: sqlalchemy.Engine | None = None
_CONNECTOR: Any = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _use_cloud_sql() -> bool:
    backend = os.getenv("DB_BACKEND", "").strip().lower()
    if backend == "sqlite":
        return False
    if backend == "cloudsql":
        return True
    return bool(os.getenv("DB_INSTANCE_CONNECTION_NAME"))


def _instance_connection_name() -> str:
    project_id = os.getenv("GCP_PROJECT_ID", "cymbal-health-prod")
    return (
        os.getenv("DB_INSTANCE_CONNECTION_NAME")
        or os.getenv("CLOUD_SQL_CONNECTION_NAME")
        or f"{project_id}:us-central1:cymbal-health-pg-main"
    )


def _iam_db_user() -> str:
    project_id = os.getenv("GCP_PROJECT_ID", "cymbal-health-prod")
    user = (
        os.getenv("DB_IAM_USER")
        or os.getenv("DB_IAM_USER_PORTAL")
        or f"cymbal-health-portal-sa@{project_id}.iam"
    )
    # Cloud SQL IAM users for service accounts omit the ".gserviceaccount.com" suffix.
    return user.removesuffix(".gserviceaccount.com")


def get_iam_db_auth_metadata() -> dict[str, Any]:
    """Returns Cloud SQL IAM Database Authentication configuration metadata."""
    use_cloud_sql = _use_cloud_sql()
    return {
        "engine": "cloudsql-postgresql-15-iam" if use_cloud_sql else "sqlite-local-mirror",
        "iam_db_authentication": True,
        "static_password_configured": False,
        "private_ip_only": os.getenv("DB_IP_TYPE", "PRIVATE").upper() == "PRIVATE",
        "instance_connection_name": _instance_connection_name(),
        "portal_db_principal": _iam_db_user(),
        "connector": "cloud-sql-python-connector+pg8000" if use_cloud_sql else "sqlite3",
    }


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------


def _create_cloud_sql_engine() -> sqlalchemy.Engine:
    from google.cloud.sql.connector import Connector, IPTypes

    global _CONNECTOR
    instance = _instance_connection_name()
    user = _iam_db_user()
    db_name = os.getenv("DB_NAME", "cymbal_health_db")
    ip_type = IPTypes.PRIVATE if os.getenv("DB_IP_TYPE", "PRIVATE").upper() == "PRIVATE" else IPTypes.PUBLIC

    # Lazy refresh fetches certificates on demand, which is the recommended mode on
    # Cloud Run because CPU is throttled outside of request handling.
    _CONNECTOR = Connector(refresh_strategy="lazy")

    def _getconn() -> Any:
        return _CONNECTOR.connect(
            instance,
            "pg8000",
            user=user,
            db=db_name,
            enable_iam_auth=True,
            ip_type=ip_type,
        )

    engine = sqlalchemy.create_engine(
        "postgresql+pg8000://",
        creator=_getconn,
        pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
        max_overflow=int(os.getenv("DB_POOL_MAX_OVERFLOW", "2")),
        pool_timeout=30,
        pool_recycle=1800,
        pool_pre_ping=True,
    )
    logger.info(
        "Cloud SQL engine configured",
        extra={"instance": instance, "db_user": user, "database": db_name, "ip_type": ip_type.value},
    )
    return engine


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS clinical_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_code TEXT UNIQUE NOT NULL,
    folio_number TEXT NOT NULL,
    patient_alias TEXT NOT NULL,
    document_masked TEXT NOT NULL,
    eps_name TEXT NOT NULL,
    specialty TEXT NOT NULL,
    cups_code TEXT NOT NULL,
    cie10_code TEXT NOT NULL,
    procedure_name TEXT NOT NULL,
    center_city TEXT NOT NULL,
    attending_physician TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    support_pdf_object TEXT NOT NULL,
    created_at TEXT NOT NULL,
    clinical_summary TEXT NOT NULL,
    patient_preparation TEXT NOT NULL,
    confidential INTEGER NOT NULL DEFAULT 0
);

CREATE VIEW IF NOT EXISTS clinical_orders_public_v AS
SELECT
    order_code, folio_number, patient_alias, document_masked, eps_name,
    specialty, cups_code, cie10_code, procedure_name, center_city,
    attending_physician, status, priority, support_pdf_object, created_at,
    clinical_summary, patient_preparation
FROM clinical_orders
WHERE confidential = 0;
"""

_INSERT_ORDER_SQL = """
INSERT INTO clinical_orders (
    order_code, folio_number, patient_alias, document_masked, eps_name,
    specialty, cups_code, cie10_code, procedure_name, center_city,
    attending_physician, status, priority, support_pdf_object,
    created_at, clinical_summary, patient_preparation, confidential
) VALUES (
    :order_code, :folio_number, :patient_alias, :document_masked, :eps_name,
    :specialty, :cups_code, :cie10_code, :procedure_name, :center_city,
    :attending_physician, :status, :priority, :support_pdf_object,
    :created_at, :clinical_summary, :patient_preparation, :confidential
)
"""


def _create_sqlite_engine() -> sqlalchemy.Engine:
    engine = sqlalchemy.create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    with engine.begin() as conn:
        raw = conn.connection.driver_connection
        raw.executescript(_SQLITE_SCHEMA)
        for row in SEED_CLINICAL_ORDERS:
            conn.execute(text(_INSERT_ORDER_SQL.replace("INSERT INTO", "INSERT OR IGNORE INTO")), dict(row))
    return engine


def get_engine() -> sqlalchemy.Engine:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            _ENGINE = _create_cloud_sql_engine() if _use_cloud_sql() else _create_sqlite_engine()
        return _ENGINE


def _is_postgres() -> bool:
    return get_engine().dialect.name == "postgresql"


def reset_database() -> None:
    """Rebuilds the local SQLite mirror (tests). Never touches Cloud SQL data."""
    global _ENGINE, _CONNECTOR
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            _ENGINE.dispose()
        if _CONNECTOR is not None:
            _CONNECTOR.close()
            _CONNECTOR = None
        _ENGINE = None if _use_cloud_sql() else _create_sqlite_engine()


@contextmanager
def _transaction(read_only: bool = False) -> Iterator[sqlalchemy.Connection]:
    engine = get_engine()
    if engine.dialect.name == "sqlite":
        # The in-memory mirror shares one connection across threads.
        with _SQLITE_LOCK, engine.begin() as conn:
            yield conn
        return
    with engine.begin() as conn:
        if read_only:
            conn.exec_driver_sql("SET TRANSACTION READ ONLY")
        yield conn


def check_database_connection() -> dict[str, Any]:
    """Readiness check: runs SELECT 1 through the configured backend."""
    metadata = get_iam_db_auth_metadata()
    try:
        with _transaction(read_only=True) as conn:
            conn.execute(text("SELECT 1")).scalar_one()
            if _is_postgres():
                metadata["current_user"] = conn.execute(text("SELECT current_user")).scalar_one()
                metadata["server_version"] = conn.execute(text("SHOW server_version")).scalar_one()
        metadata["connected"] = True
    except Exception as exc:  # pragma: no cover - surfaced to readiness probe
        logger.exception("Database readiness check failed")
        metadata["connected"] = False
        metadata["error"] = type(exc).__name__
    return metadata


# ---------------------------------------------------------------------------
# Row helpers
# ---------------------------------------------------------------------------


def _format_timestamp(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(COLOMBIA_TZ).strftime("%Y-%m-%d %H:%M COT")
    return value


def _row_to_dict(row: sqlalchemy.Row) -> dict[str, Any]:
    return {key: _format_timestamp(val) for key, val in row._mapping.items()}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def list_public_orders(status_filter: str | None = None) -> list[dict[str, Any]]:
    with _transaction(read_only=True) as conn:
        if status_filter and status_filter.upper() != "ALL":
            rows = conn.execute(
                text(
                    "SELECT * FROM clinical_orders_public_v "
                    "WHERE UPPER(status) = UPPER(:status) ORDER BY order_code DESC"
                ),
                {"status": status_filter.strip()},
            ).fetchall()
        else:
            rows = conn.execute(
                text("SELECT * FROM clinical_orders_public_v ORDER BY order_code DESC")
            ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_public_order(order_code: str) -> dict[str, Any] | None:
    with _transaction(read_only=True) as conn:
        row = conn.execute(
            text("SELECT * FROM clinical_orders_public_v WHERE order_code = :code"),
            {"code": order_code.strip()},
        ).fetchone()
    return _row_to_dict(row) if row else None


def search_orders(query: str) -> dict[str, Any]:
    """Searches clinical authorizations using parameterized SQL on `clinical_orders_public_v`."""
    cleaned = (query or "").strip()
    if not cleaned:
        items = list_public_orders()
        return {"items": items, "count": len(items)}

    like_op = "ILIKE" if _is_postgres() else "LIKE"
    columns = ("order_code", "cups_code", "specialty", "procedure_name", "patient_alias", "center_city")
    where = " OR ".join(f"{col} {like_op} :pattern" for col in columns)
    with _transaction(read_only=True) as conn:
        rows = conn.execute(
            text(f"SELECT * FROM clinical_orders_public_v WHERE {where} ORDER BY order_code DESC"),
            {"pattern": f"%{cleaned}%"},
        ).fetchall()
    items = [_row_to_dict(r) for r in rows]
    return {"items": items, "count": len(items)}


def _next_order_number(conn: sqlalchemy.Connection) -> int:
    if conn.dialect.name == "postgresql":
        # Dedicated sequence created by db/migrations/V001; safe under concurrency.
        return int(conn.execute(text("SELECT nextval('clinical_order_code_seq')")).scalar_one())
    total = conn.execute(
        text("SELECT COUNT(*) FROM clinical_orders WHERE confidential = 0")
    ).scalar_one()
    return ORDER_CODE_FIRST_NUMBER + int(total)


def create_clinical_order(
    *,
    patient_alias: str,
    document_masked: str,
    eps_name: str,
    specialty: str,
    cups_code: str,
    cie10_code: str,
    procedure_name: str,
    center_city: str,
    attending_physician: str,
    priority: str,
    clinical_summary: str,
    patient_preparation: str | None = None,
) -> dict[str, Any]:
    prep = (
        patient_preparation.strip()
        if patient_preparation and patient_preparation.strip()
        else DEFAULT_PREFILLED_ORDER["patient_preparation"]
    )
    now = datetime.now(COLOMBIA_TZ)
    with _transaction() as conn:
        next_num = _next_order_number(conn)
        order_code = f"ORD-2026-{next_num}"
        params = {
            "order_code": order_code,
            "folio_number": f"AUT-2026-00{7900 + next_num}",
            "patient_alias": patient_alias.strip(),
            "document_masked": document_masked.strip(),
            "eps_name": eps_name.strip(),
            "specialty": specialty.strip(),
            "cups_code": cups_code.strip(),
            "cie10_code": cie10_code.strip(),
            "procedure_name": procedure_name.strip(),
            "center_city": center_city.strip(),
            "attending_physician": attending_physician.strip(),
            "status": "AUTORIZADA",
            "priority": priority.strip().upper(),
            "support_pdf_object": f"soportes/{now:%Y/%m}/{order_code}.pdf",
            "created_at": now if conn.dialect.name == "postgresql" else now.strftime("%Y-%m-%d %H:%M COT"),
            "clinical_summary": clinical_summary.strip(),
            "patient_preparation": prep,
            "confidential": 0,
        }
        conn.execute(text(_INSERT_ORDER_SQL), params)
    created = get_public_order(order_code)
    assert created is not None
    return created
