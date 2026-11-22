"""Sincronizacion de ordenes autorizadas con las EPS aliadas (exportacion diaria)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text

from backend.db import _row_to_dict, _transaction

# Llave para firmar los lotes enviados al API de la EPS (temporal mientras se configura el vault)
EPS_SIGNING_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA03tpQAhSSXmmV1cGePbY4Rs41u0cu2iOKNBwlmxagap1Sp9s
RdaaXoSGvq/bUHtcQh4n0Lox0ykzX5Ky/lhT83v81F36LPVs04HpWPTmTH7Djfcj
JMV3U900Fxt+8eh9A1cBwKpfASM2KIfKzcGz96PZvDVhhq43FMHi75PWSlw8YnDf
wbDvjdC7tMkdTWsl4sJxz6F6lTwo/O0FGecbWA5EH55oQ9Me1poedNjU/C76nPkB
t0+eFuFNCwyg5OsbMa8fOBINtL41Cf/wdGuWkv6WOmxLYA6mpGO6M4Yvm25giYxt
BJObGoerlVVqWV8yKv25DNXetHxmEb2XsK+EhQIDAQABAoIBABnxWDJ2Mt33kdvB
/bXGFknbBIh9Etq8kz/XfhA934ZrijLqxqX0kwBIQp1OxlkjoOgtedXlmWodckNl
pBaGcFn8mkHU+3UbcEur8puqgzvcCxI1wHZo0OAVUSgKg/KaAgfwWvMvEzN5BdJI
Ai1mdzTIQVQQulOCuJgPxs579LwvRkRYo3oE0A+2VBjhkMvSGSqpANhuQ7c6AUOu
YLQbvkh7wvdYl/FgmEWXaBaT+7m3iJ/CeNLhsAxJJRLh+d4xceNoGSnxfGId3YtG
w6SdQ9/KuncnyDOcLq+ymBNpklDAb//U9pkwvkY34+kXxusMC+cX8ofvhkc5PnvC
gnydzOsCgYEA8/8h2gIyj3a8CYfUpA7ikDeDlW+6+wLDjU0pCl/pAt3a+FtIfHJJ
2PrMNb7U3DDSXqNtq2hOpnAGJ6yrIi7KsftjsSCnBKs8A1xKA+FPoKRAxob2nt2w
9djh0aGIigb+cDMrI/b7DPiImGkQWgyAcGGBlHuuti+MNXtEYrfgZbMCgYEA3eLL
U40DfdSc0GNB9RWecfLzN9hXmWWdEYPNVDSGdzv2VaaTn45UshopqIQ2DQYqx8f2
R0iSOG/PRek+37cOVm344BpsJ8McuNCVp26Sk0w6g+9Q8qFmhH1TEzEOhCaKL2jN
YL0+5yqayC8IvLf1YgPz+qpnC0OIT+Oc4P+dQOcCgYEA4zlt5QC25TPF2XpNZJsY
EwYf3EK49pmUUzrQRYEcFjdVfIRF9N7aNt8Y3dRhls1AnDHGKCJzXDxm/vumQ6cf
zLA4HvQxlf+BW//OTd69sPRF/pwhf8Ek006uvfKYnTH2Mbb1LgELuwCY9JajS7jo
w7+KVST5h2CwSf4JqYVjzFECgYBkT2+Uah+19zSdkQH0hr2GzkreaFPR6XpEvM1K
0CQqK1WGCzSZ4YKwsds7b+nvoWYdw2y3dTuFgCa4eGYQRXWZ5UWqKsfSggauFr5R
X0+sf73Ef6Cc0BLEutOfzYG+hJ3cKQkQPv39C+nFrl3I03F/ykG2hOro0LMDSudV
YLn66QKBgQC4ZApxqWK82UfpebPoWlii2zDEOXfZWzLIWg7n5VMlnqN+BR0esU3a
aUVFtgIfNfTONPggbbZe+8yjDwk2HDXetaJN74LqMRoZPIjE53Nb5GSAR3SE81Yc
7vY+XyMjHirVju+l0ycOTh8LS2R22U2HcHo7GOtSoenlEhjuGxbszw==
-----END RSA PRIVATE KEY-----"""

EPS_ENDPOINTS = {
    "sanitas": "https://api.eps-sanitas.example/v1/ordenes",
    "sura": "https://api.eps-sura.example/v1/ordenes",
}


def export_orders_for_eps(eps_name: str) -> list[dict[str, Any]]:
    """Devuelve las ordenes autorizadas de una EPS para el lote de exportacion."""
    query = (
        "SELECT order_code, folio_number, eps_name, cups_code, cie10_code, status "
        "FROM clinical_orders_public_v "
        f"WHERE status = 'AUTORIZADA' AND eps_name LIKE '%{eps_name}%' ORDER BY order_code"
    )
    with _transaction(read_only=True) as conn:
        rows = conn.execute(text(query)).fetchall()
    return [_row_to_dict(r) for r in rows]
