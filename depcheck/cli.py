"""Interfaz de línea de comandos: depcheck scan <manifiesto>"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .models import Severity
from .report import to_html, to_json, to_text
from .scanner import scan_manifest

DESC = ("Revisa un requirements.txt o package.json contra OSV.dev (base de datos pública "
        "de vulnerabilidades de código abierto). Solo lee el archivo local y consulta la "
        "API pública; no se conecta a ningún servidor tuyo.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="depcheck", description=DESC)
    p.add_argument("--version", action="version", version=f"depcheck {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Revisa un manifiesto de dependencias")
    s.add_argument("manifest", help="requirements.txt o package.json")
    s.add_argument("--ecosystem", choices=["PyPI", "npm"], help="Forzar el ecosistema (si no se detecta por el nombre)")
    s.add_argument("--format", choices=["text", "json", "html"], default="text")
    s.add_argument("-o", "--output", help="Archivo de salida (por defecto stdout)")
    s.add_argument("--fail-on", choices=[x.name.lower() for x in Severity], default=None,
                   help="Código de salida 2 si hay hallazgos >= severidad (útil en CI/CD)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    result = scan_manifest(args.manifest, ecosystem=args.ecosystem)

    if args.format == "json":
        out = to_json(result)
    elif args.format == "html":
        out = to_html(result)
    else:
        out = to_text(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Reporte guardado en {args.output}")
    else:
        print(out)

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
