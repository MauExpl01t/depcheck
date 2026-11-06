from depcheck.models import Severity
from depcheck.parsers import parse_package_json, parse_requirements_txt
from depcheck.report import to_html, to_json, to_text
from depcheck.scanner import detect_ecosystem, scan_manifest


# ---------- parsers ----------
def test_parse_requirements_txt(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("django==3.2.0\nrequests==2.31.0  # comentario\nflask>=2.0\n\n-e .\n", encoding="utf-8")
    packages, notes = parse_requirements_txt(str(f))
    assert ("django", "3.2.0") in packages
    assert ("requests", "2.31.0") in packages
    assert len(packages) == 2  # flask sin version exacta no cuenta
    assert any("flask" in n for n in notes)


def test_parse_package_json(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(
        '{"dependencies": {"lodash": "^4.17.15"}, "devDependencies": {"left-pad": "~1.0.0"}}',
        encoding="utf-8")
    packages, notes = parse_package_json(str(f))
    assert ("lodash", "4.17.15") in packages
    assert ("left-pad", "1.0.0") in packages
    assert notes == []


def test_detect_ecosystem():
    assert detect_ecosystem("requirements.txt") == "PyPI"
    assert detect_ecosystem("package.json") == "npm"
    assert detect_ecosystem("Gemfile") is None


# ---------- escaneo end-to-end ----------
def test_scan_requirements_finds_vuln(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("django==3.2.0\nrequests==2.31.0\n", encoding="utf-8")
    result = scan_manifest(str(f))

    assert result.packages_checked == 2
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.package == "django"
    assert finding.vuln_id == "GHSA-DJANGO-FAKE"
    assert finding.severity == Severity.HIGH
    assert finding.fixed_version == "3.2.5"


def test_scan_package_json_unspecified_severity_defaults_to_medium(tmp_path):
    f = tmp_path / "package.json"
    f.write_text('{"dependencies": {"lodash": "^4.17.15"}}', encoding="utf-8")
    result = scan_manifest(str(f))

    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.MEDIUM
    assert result.findings[0].fixed_version == "4.17.21"


def test_scan_unknown_extension_reports_error(tmp_path):
    f = tmp_path / "Gemfile"
    f.write_text("gem 'rails'", encoding="utf-8")
    result = scan_manifest(str(f))
    assert result.errors
    assert result.findings == []


def test_scan_respects_ecosystem_override(tmp_path):
    f = tmp_path / "deps.txt"
    f.write_text("django==3.2.0\n", encoding="utf-8")
    result = scan_manifest(str(f), ecosystem="PyPI")
    assert len(result.findings) == 1


# ---------- reportes ----------
def test_reports_render_without_error(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("django==3.2.0\n", encoding="utf-8")
    result = scan_manifest(str(f))

    assert "GHSA-DJANGO-FAKE" in to_json(result)
    text = to_text(result)
    assert "django" in text and "3.2.5" in text
    html = to_html(result)
    assert "<script" not in html.lower()
    assert "SQL injection" in html
