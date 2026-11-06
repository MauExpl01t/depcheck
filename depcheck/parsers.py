"""Extrae (nombre, versión exacta) de un manifiesto de dependencias. Para
poder consultar OSV.dev hace falta una versión exacta, no un rango: las
líneas sin versión fijada (o con rangos complejos en package.json) se
reportan como nota, no se omiten en silencio."""
from __future__ import annotations

import json
import re

REQ_LINE_RX = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)")
SEMVER_PREFIX_RX = re.compile(r"^[\^~>=<\s]*")
SEMVER_RX = re.compile(r"^\d+\.\d+\.\d+")


def parse_requirements_txt(path: str) -> tuple[list[tuple[str, str]], list[str]]:
    packages: list[tuple[str, str]] = []
    notes: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = REQ_LINE_RX.match(line)
            if m:
                packages.append((m.group(1), m.group(2)))
            else:
                notes.append(f"línea {line_no}: '{line}' no tiene versión exacta fijada (==); se omite")
    return packages, notes


def parse_package_json(path: str) -> tuple[list[tuple[str, str]], list[str]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    packages: list[tuple[str, str]] = []
    notes: list[str] = []
    for section in ("dependencies", "devDependencies"):
        for name, raw_version in (data.get(section) or {}).items():
            version = SEMVER_PREFIX_RX.sub("", str(raw_version)).split(" ")[0].split("||")[0].strip()
            if not SEMVER_RX.match(version):
                notes.append(f"{name}: '{raw_version}' no es una versión simple; se omite "
                              "(usa package-lock.json para versiones exactas resueltas)")
                continue
            packages.append((name, version))
    return packages, notes
