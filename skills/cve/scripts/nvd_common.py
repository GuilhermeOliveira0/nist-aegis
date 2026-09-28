"""Base compartilhada dos scripts de consulta de CVE da NVD.

Nada aqui imprime o valor de NVD_API_KEY. A chave é lida do ambiente e usada
apenas como header da requisição.
"""

import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
SCHEMA_VERSION = 1

# Rate limit publicado pela NVD: 5 requisições / 30 s sem chave, 50 / 30 s com chave.
SLEEP_WITH_KEY = 0.7
SLEEP_NO_KEY = 6.5

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS cves (
    cve_id         TEXT PRIMARY KEY,
    published      TEXT,
    last_modified  TEXT,
    vuln_status    TEXT,
    description    TEXT,
    description_lc TEXT,
    cvss_version   TEXT,
    base_score     REAL,
    base_severity  TEXT,
    severity_rank  INTEGER,
    vector_string  TEXT,
    cwes           TEXT,
    raw            TEXT
);
CREATE INDEX IF NOT EXISTS idx_cves_sev ON cves(severity_rank);
CREATE INDEX IF NOT EXISTS idx_cves_mod ON cves(last_modified);
CREATE TABLE IF NOT EXISTS cpes (
    cve_id           TEXT,
    criteria         TEXT,
    vendor_product   TEXT,
    version_start    TEXT,
    version_start_op TEXT,
    version_end      TEXT,
    version_end_op   TEXT
);
CREATE INDEX IF NOT EXISTS idx_cpes_vp  ON cpes(vendor_product);
CREATE INDEX IF NOT EXISTS idx_cpes_cve ON cpes(cve_id);
"""


def api_key():
    """Devolve a chave do ambiente, ou None. Nunca a imprime."""
    key = os.environ.get("NVD_API_KEY", "").strip()
    return key or None


def db_path(raw_path):
    return os.path.abspath(os.path.expanduser(raw_path))


def connect(path, create=True):
    resolved = db_path(path)
    if not create and not os.path.exists(resolved):
        sys.exit("ERRO: base não encontrada em %s. Rode download_db.py primeiro." % resolved)
    parent = os.path.dirname(resolved)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(resolved)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_schema(conn):
    conn.executescript(SCHEMA)
    meta_set(conn, "schema_version", str(SCHEMA_VERSION))
    conn.commit()


def meta_get(conn, key, default=None):
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    except sqlite3.OperationalError:
        return default
    return row["value"] if row else default


def meta_set(conn, key, value):
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def request_json(params, key, timeout=90, max_retries=6):
    """GET na API 2.0 da NVD com backoff exponencial. Devolve o JSON decodificado."""
    url = API_URL + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "nvd-vuln-check/1.0"}
    if key:
        headers["apiKey"] = key
    delay = 4.0
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503, 504) and attempt < max_retries:
                sys.stderr.write(
                    "  HTTP %d, tentativa %d/%d, aguardando %.0fs\n"
                    % (exc.code, attempt, max_retries, delay)
                )
                time.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            if exc.code == 404:
                return None
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt < max_retries:
                sys.stderr.write(
                    "  rede: %s, tentativa %d/%d, aguardando %.0fs\n"
                    % (type(exc).__name__, attempt, max_retries, delay)
                )
                time.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            raise
    raise RuntimeError("consulta à NVD falhou após %d tentativas" % max_retries)


def extract_metrics(cve):
    """Devolve (versao_cvss, score, severidade, vetor) pela ordem v3.1 > v3.0 > v2."""
    metrics = cve.get("metrics") or {}
    for field, label in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(field) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            return (
                label,
                data.get("baseScore"),
                (data.get("baseSeverity") or "").upper(),
                data.get("vectorString"),
            )
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        entry = entries[0]
        data = entry.get("cvssData") or {}
        return (
            "2.0",
            data.get("baseScore"),
            (entry.get("baseSeverity") or "").upper(),
            data.get("vectorString"),
        )
    return (None, None, "", None)


def extract_description(cve):
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            return desc.get("value") or ""
    descs = cve.get("descriptions") or []
    return (descs[0].get("value") or "") if descs else ""


def extract_cwes(cve):
    found = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value") or ""
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return ",".join(found)


def extract_cpes(cve):
    """Devolve linhas (criteria, vendor_product, vstart, vstart_op, vend, vend_op)."""
    rows = []
    seen = set()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                if not criteria or criteria in seen:
                    continue
                seen.add(criteria)
                parts = criteria.split(":")
                vendor_product = (
                    "%s:%s" % (parts[3], parts[4]) if len(parts) > 4 else ""
                )
                vstart = vstart_op = vend = vend_op = None
                if match.get("versionStartIncluding"):
                    vstart, vstart_op = match["versionStartIncluding"], ">="
                elif match.get("versionStartExcluding"):
                    vstart, vstart_op = match["versionStartExcluding"], ">"
                if match.get("versionEndIncluding"):
                    vend, vend_op = match["versionEndIncluding"], "<="
                elif match.get("versionEndExcluding"):
                    vend, vend_op = match["versionEndExcluding"], "<"
                rows.append(
                    (criteria, vendor_product, vstart, vstart_op, vend, vend_op)
                )
    return rows


def upsert_cve(conn, cve, store_raw=True):
    cve_id = cve.get("id")
    if not cve_id:
        return 0
    version, score, severity, vector = extract_metrics(cve)
    description = extract_description(cve)
    conn.execute(
        "INSERT INTO cves (cve_id, published, last_modified, vuln_status, description,"
        " description_lc, cvss_version, base_score, base_severity, severity_rank,"
        " vector_string, cwes, raw)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(cve_id) DO UPDATE SET"
        " published=excluded.published, last_modified=excluded.last_modified,"
        " vuln_status=excluded.vuln_status, description=excluded.description,"
        " description_lc=excluded.description_lc, cvss_version=excluded.cvss_version,"
        " base_score=excluded.base_score, base_severity=excluded.base_severity,"
        " severity_rank=excluded.severity_rank, vector_string=excluded.vector_string,"
        " cwes=excluded.cwes, raw=excluded.raw",
        (
            cve_id,
            cve.get("published"),
            cve.get("lastModified"),
            cve.get("vulnStatus"),
            description,
            description.lower(),
            version,
            score,
            severity,
            SEVERITY_RANK.get(severity, 0),
            vector,
            extract_cwes(cve),
            json.dumps(cve, separators=(",", ":")) if store_raw else None,
        ),
    )
    conn.execute("DELETE FROM cpes WHERE cve_id = ?", (cve_id,))
    rows = extract_cpes(cve)
    if rows:
        conn.executemany(
            "INSERT INTO cpes (cve_id, criteria, vendor_product, version_start,"
            " version_start_op, version_end, version_end_op) VALUES (?,?,?,?,?,?,?)",
            [(cve_id,) + row for row in rows],
        )
    return 1


def min_rank(name):
    if not name:
        return 0
    rank = SEVERITY_RANK.get(name.upper())
    if rank is None:
        sys.exit(
            "ERRO: severidade inválida %r. Use LOW, MEDIUM, HIGH ou CRITICAL." % name
        )
    return rank


def format_cve(row, width=100):
    score = "n/d" if row["base_score"] is None else "%.1f" % row["base_score"]
    severity = row["base_severity"] or "n/d"
    head = "%s  %s  %s (CVSS %s)" % (
        row["cve_id"],
        score,
        severity,
        row["cvss_version"] or "n/d",
    )
    desc = (row["description"] or "").replace("\n", " ").strip()
    if len(desc) > width:
        desc = desc[: width - 1] + "…"
    lines = [head, "  " + desc]
    if row["cwes"]:
        lines.append("  CWE: %s" % row["cwes"])
    return "\n".join(lines)
