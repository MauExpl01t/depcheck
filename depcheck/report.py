"""Reportes en texto, JSON y HTML."""
from __future__ import annotations

import json
from html import escape

from .models import ScanResult, Severity

COLORS = {"CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#c2410c", "LOW": "#a16207", "INFO": "#475569"}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def to_text(result: ScanResult) -> str:
    lines = [f"Manifiesto   : {result.manifest} ({result.ecosystem})",
              f"Paquetes     : {result.packages_checked} revisados",
              "Resumen      : " + (", ".join(f"{k}={v}" for k, v in result.summary().items() if v) or "sin hallazgos"),
              ""]
    for f in result.sorted_findings():
        lines.append(f"[{f.severity.label.upper()}] {f.package} {f.version}  ({f.vuln_id})")
        lines.append(f"    {f.summary}")
        if f.fixed_version:
            lines.append(f"    Solución: actualiza a {f.fixed_version} o superior")
        lines.append(f"    Referencia: {f.reference}")
        lines.append("")
    for n in result.notes:
        lines.append(f"[nota] {n}")
    for e in result.errors:
        lines.append(f"[!] {e}")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    summ = result.summary()
    chips = "".join(
        f'<span class="chip" style="background:{COLORS[k]}">{Severity[k].label}: {v}</span>'
        for k, v in summ.items() if v) or "<span>Sin hallazgos</span>"

    cards = []
    for f in result.sorted_findings():
        col = COLORS[f.severity.name]
        fix = f"<p><strong>Solución:</strong> actualiza a {escape(f.fixed_version)} o superior</p>" if f.fixed_version else ""
        cards.append(
            f'<article style="border-left:6px solid {col}"><h3><span class="sev" style="background:{col}">'
            f'{f.severity.label}</span> {escape(f.package)} {escape(f.version)} <small>({escape(f.vuln_id)})</small></h3>'
            f'<p>{escape(f.summary)}</p>{fix}'
            f'<p class="ref"><a href="{escape(f.reference)}" rel="noopener noreferrer">Referencia</a></p></article>')
    notes = "".join(f"<li>{escape(n)}</li>" for n in result.notes)
    notes = f"<h2>Notas</h2><ul>{notes}</ul>" if notes else ""
    errs = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
    errs = f"<h2>Advertencias</h2><ul>{errs}</ul>" if errs else ""

    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DepCheck - {escape(result.manifest)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#0f172a;background:#f8fafc}}
h1{{margin-bottom:.2rem}} .meta{{color:#475569}}
.chip{{color:#fff;padding:.2rem .6rem;border-radius:999px;margin-right:.4rem;font-size:.85rem}}
article{{background:#fff;padding:1rem 1.2rem;margin:1rem 0;border-radius:8px;box-shadow:0 1px 3px #0001}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.8rem;vertical-align:middle}}
.ref{{font-size:.85rem}}
</style></head><body>
<h1>Reporte DepCheck</h1>
<p class="meta">{escape(result.manifest)} · {escape(result.ecosystem)} · {result.packages_checked} paquetes revisados</p>
<p>{chips}</p>
<h2>Hallazgos ({len(result.findings)})</h2>
{''.join(cards) or '<p>No se encontraron vulnerabilidades conocidas.</p>'}
{notes}
{errs}
</body></html>"""
