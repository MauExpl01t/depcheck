"""API de OSV.dev simulada, para no depender de internet ni de que una
versión específica siga teniendo la misma vulnerabilidad con el tiempo."""
from __future__ import annotations

import pytest

FAKE_BATCH = {
    ("django", "3.2.0", "PyPI"): ["GHSA-DJANGO-FAKE"],
    ("requests", "2.31.0", "PyPI"): [],
    ("lodash", "4.17.15", "npm"): ["GHSA-LODASH-FAKE"],
    ("left-pad", "1.0.0", "npm"): [],
}

FAKE_VULNS = {
    "GHSA-DJANGO-FAKE": {
        "id": "GHSA-DJANGO-FAKE",
        "summary": "SQL injection de prueba en un QuerySet.",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"fixed": "3.2.5"}]}],
        }],
    },
    "GHSA-LODASH-FAKE": {
        "id": "GHSA-LODASH-FAKE",
        "summary": "Prototype pollution de prueba.",
        "database_specific": {},  # sin severidad especificada, a propósito
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }],
    },
}


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def fake_post(url, json=None, timeout=None):
    results = []
    for q in json["queries"]:
        key = (q["package"]["name"], q["version"], q["package"]["ecosystem"])
        ids = FAKE_BATCH.get(key, [])
        results.append({"vulns": [{"id": i} for i in ids]})
    return FakeResponse({"results": results})


def fake_get(url, timeout=None):
    vuln_id = url.rsplit("/", 1)[-1]
    return FakeResponse(FAKE_VULNS[vuln_id])


@pytest.fixture(autouse=True)
def fake_osv(monkeypatch):
    monkeypatch.setattr("depcheck.osv.requests.post", fake_post)
    monkeypatch.setattr("depcheck.osv.requests.get", fake_get)
