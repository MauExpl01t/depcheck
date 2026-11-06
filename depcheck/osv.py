"""Cliente de la API pública de OSV.dev (Open Source Vulnerabilities),
mantenida por Google y la comunidad. Gratis, sin API key. Primero una
consulta por lotes (un paquete por petición, pero todas en una sola
llamada HTTP) para saber qué IDs de vulnerabilidad afectan a cada versión
exacta; después se pide el detalle de cada ID encontrado."""
from __future__ import annotations

import requests

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
TIMEOUT = 20.0

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def query_batch(packages: list[tuple[str, str]], ecosystem: str) -> dict[tuple[str, str], list[str]]:
    """packages: [(nombre, version)]. Devuelve {(nombre,version): [ids]}."""
    if not packages:
        return {}
    queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version}
               for name, version in packages]
    resp = requests.post(BATCH_URL, json={"queries": queries}, timeout=TIMEOUT)
    resp.raise_for_status()
    results = resp.json().get("results", [])
    return {pkg: [v["id"] for v in (r.get("vulns") or [])] for pkg, r in zip(packages, results)}


def fetch_vuln(vuln_id: str) -> dict:
    resp = requests.get(VULN_URL.format(id=vuln_id), timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def extract_severity_label(vuln: dict) -> str:
    """Prefiere la clasificación que ya trae la fuente (GHSA, PYSEC...);
    si no la especifica, se marca para revisión manual en vez de adivinar."""
    label = (vuln.get("database_specific") or {}).get("severity")
    if label and label.upper() in SEVERITY_RANK:
        return label.upper()
    return "SIN ESPECIFICAR"


def extract_fixed_version(vuln: dict, ecosystem: str) -> str | None:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None
