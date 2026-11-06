"""Orquesta: detecta el ecosistema por el nombre del archivo, parsea,
consulta OSV.dev por lotes, y pide el detalle de cada vulnerabilidad única
encontrada (una sola vez por ID, aunque afecte a varios paquetes)."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import osv
from .models import Finding, ScanResult, Severity
from .parsers import parse_package_json, parse_requirements_txt

MAX_WORKERS = 10

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    "SIN ESPECIFICAR": Severity.MEDIUM,
}


def detect_ecosystem(manifest_path: str) -> str | None:
    name = os.path.basename(manifest_path).lower()
    if name == "package.json":
        return "npm"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "PyPI"
    return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def scan_manifest(manifest_path: str, ecosystem: str | None = None) -> ScanResult:
    eco = ecosystem or detect_ecosystem(manifest_path)
    result = ScanResult(manifest=manifest_path, ecosystem=eco or "desconocido", started_at=_now())
    if eco is None:
        result.errors.append(
            "No se pudo determinar el ecosistema por el nombre del archivo; usa --ecosystem.")
        result.finished_at = _now()
        return result

    try:
        if eco == "npm":
            packages, notes = parse_package_json(manifest_path)
        else:
            packages, notes = parse_requirements_txt(manifest_path)
    except (OSError, ValueError) as exc:
        result.errors.append(f"No se pudo leer '{manifest_path}': {exc}")
        result.finished_at = _now()
        return result

    result.notes.extend(notes)
    result.packages_checked = len(packages)

    try:
        matches = osv.query_batch(packages, eco)
    except Exception as exc:
        result.errors.append(f"No se pudo consultar OSV.dev: {type(exc).__name__}: {exc}")
        result.finished_at = _now()
        return result

    unique_ids = sorted({vid for ids in matches.values() for vid in ids})

    def fetch(vuln_id: str) -> tuple[str, dict | None, str | None]:
        try:
            return vuln_id, osv.fetch_vuln(vuln_id), None
        except Exception as exc:
            return vuln_id, None, str(exc)

    vuln_cache: dict[str, dict] = {}
    if unique_ids:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for vuln_id, vuln, error in pool.map(fetch, unique_ids):
                if error:
                    result.errors.append(f"No se pudo obtener el detalle de {vuln_id}: {error}")
                else:
                    vuln_cache[vuln_id] = vuln

    for (name, version), vuln_ids in matches.items():
        for vuln_id in vuln_ids:
            vuln = vuln_cache.get(vuln_id)
            if vuln is None:
                continue
            label = osv.extract_severity_label(vuln)
            result.findings.append(Finding(
                package=name, version=version, vuln_id=vuln_id,
                severity=SEVERITY_MAP.get(label, Severity.MEDIUM),
                summary=vuln.get("summary") or vuln.get("details", "")[:200] or "Sin descripción.",
                fixed_version=osv.extract_fixed_version(vuln, eco),
                reference=f"https://osv.dev/vulnerability/{vuln_id}"))

    result.finished_at = _now()
    return result
