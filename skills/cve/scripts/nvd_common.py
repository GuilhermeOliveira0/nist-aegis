"""Base compartilhada dos scripts de consulta de CVE da NVD.

Nada aqui imprime o valor de NVD_API_KEY. A chave é lida do ambiente e usada
apenas como header da requisição.
"""

import argparse
import json
import os
import pathlib
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
SCHEMA_VERSION = 2
# Versão da lógica de extração que preencheu as linhas. Sobe quando extract_* muda; uma base
# com versão menor precisa de `download_db.py --reindex` para ganhar os campos novos.
DATA_VERSION = 2

# Rate limit publicado pela NVD: 5 requisições / 30 s sem chave, 50 / 30 s com chave.
SLEEP_WITH_KEY = 0.7
SLEEP_NO_KEY = 6.5

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RANK_NAME = {rank: name for name, rank in SEVERITY_RANK.items()}
SEVERITY_CHOICES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Códigos de saída comuns a todos os scripts.
EXIT_OK = 0      # consulta feita, com resultado
EXIT_NONE = 1    # consulta feita, nenhum resultado
EXIT_USAGE = 2   # argumento inválido (é também o código do argparse)
EXIT_ERROR = 3   # falha de execução: base ausente, rede, API ou erro inesperado

# Prioridade de exibição: a primeira versão presente é a mostrada. A v2 fica por último porque
# a escala dela não tem CRITICAL.
METRIC_ORDER = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)

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
    raw            TEXT,
    cvss_source    TEXT,
    cvss_type      TEXT,
    kev_added      TEXT
);
CREATE TABLE IF NOT EXISTS cpes (
    cve_id           TEXT,
    criteria         TEXT,
    vendor_product   TEXT,
    version_start    TEXT,
    version_start_op TEXT,
    version_end      TEXT,
    version_end_op   TEXT,
    match_id         TEXT,
    vulnerable       INTEGER,
    cpe_version      TEXT,
    cpe_update       TEXT,
    target_sw        TEXT
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_cves_sev ON cves(severity_rank);
CREATE INDEX IF NOT EXISTS idx_cves_mod ON cves(last_modified);
CREATE INDEX IF NOT EXISTS idx_cpes_vp  ON cpes(vendor_product);
CREATE INDEX IF NOT EXISTS idx_cpes_cve ON cpes(cve_id);
"""

# Colunas acrescentadas no esquema 2, para migrar bases criadas pelo esquema 1.
MIGRATIONS = {
    "cves": (("cvss_source", "TEXT"), ("cvss_type", "TEXT"), ("kev_added", "TEXT")),
    "cpes": (
        ("match_id", "TEXT"),
        ("vulnerable", "INTEGER"),
        ("cpe_version", "TEXT"),
        ("cpe_update", "TEXT"),
        ("target_sw", "TEXT"),
    ),
}


class NvdRequestError(RuntimeError):
    """Falha ao consultar a API da NVD: HTTP de erro, rede ou resposta inválida."""


# ---------------------------------------------------------------- saída e ambiente

def configure_stdio():
    """Força UTF-8 na saída. No Windows, stdout em pipe usa cp1252 e quebra com caracteres
    comuns em descrição de CVE (ex.: U+2011, U+2264), com o mesmo código de saída de
    "sem resultados"."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def silence_broken_pipe():
    """Leitor da saída fechou o pipe (ex.: `| head`): descarta o resto sem traceback."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def api_key():
    """Devolve a chave do ambiente, ou None. Nunca a imprime."""
    key = os.environ.get("NVD_API_KEY", "").strip()
    return key or None


def positive_int(maximum):
    """Tipo de argparse para inteiro entre 1 e `maximum`."""
    def parse(texto):
        try:
            valor = int(texto)
        except ValueError:
            raise argparse.ArgumentTypeError("não é um número inteiro: %r" % texto)
        if not 1 <= valor <= maximum:
            raise argparse.ArgumentTypeError("deve estar entre 1 e %d" % maximum)
        return valor
    return parse


# ---------------------------------------------------------------- base local

def db_path(raw_path):
    return os.path.abspath(os.path.expanduser(raw_path))


def connect(path, create=True, readonly=False):
    """Abre a base. `create=False` levanta FileNotFoundError se o arquivo não existir;
    `readonly=True` abre em modo só leitura, sem alterar o journal."""
    resolved = db_path(path)
    if not create and not os.path.exists(resolved):
        raise FileNotFoundError("base não encontrada em %s — rode download_db.py primeiro" % resolved)
    if readonly:
        conn = sqlite3.connect(pathlib.Path(resolved).as_uri() + "?mode=ro", uri=True)
    else:
        parent = os.path.dirname(resolved)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(resolved)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(conn, table):
    return {row[1] for row in conn.execute("PRAGMA table_info(%s)" % table)}


def init_schema(conn):
    """Cria as tabelas ou migra uma base do esquema 1 acrescentando as colunas novas."""
    conn.executescript(SCHEMA)
    for table, columns in MIGRATIONS.items():
        existing = table_columns(conn, table)
        for name, kind in columns:
            if name not in existing:
                conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, kind))
    conn.executescript(INDEXES)
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


# ---------------------------------------------------------------- API da NVD

def request_json(params, key, timeout=90, max_retries=6):
    """GET na API 2.0 da NVD com backoff exponencial. Devolve o JSON decodificado ou levanta
    NvdRequestError — inclusive em 404, que a NVD usa para parâmetro recusado, nunca para
    "fim da paginação"."""
    url = API_URL + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "nist-aegis/1.2"}
    if key:
        headers["apiKey"] = key
    delay = 4.0
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 500, 502, 503, 504) and attempt < max_retries:
                sys.stderr.write(
                    "  HTTP %d, tentativa %d/%d, aguardando %.0fs\n"
                    % (exc.code, attempt, max_retries, delay)
                )
                time.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            detalhe = exc.headers.get("message") if exc.headers else None
            raise NvdRequestError(
                "a NVD respondeu HTTP %d%s" % (exc.code, (": " + detalhe) if detalhe else "")
            )
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt < max_retries:
                sys.stderr.write(
                    "  rede: %s, tentativa %d/%d, aguardando %.0fs\n"
                    % (type(exc).__name__, attempt, max_retries, delay)
                )
                time.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            raise NvdRequestError("falha de rede ao consultar a NVD: %s" % type(exc).__name__)
        except ValueError:
            raise NvdRequestError("a NVD devolveu uma resposta que não é JSON válido")
    raise NvdRequestError("consulta à NVD falhou após %d tentativas" % max_retries)


# ---------------------------------------------------------------- extração de um registro

def _metric_fields(entry, label):
    data = entry.get("cvssData") or {}
    severity = (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
    return {
        "version": label,
        "score": data.get("baseScore"),
        "severity": severity,
        "vector": data.get("vectorString"),
        "source": entry.get("source"),
        "type": entry.get("type"),
    }


def extract_metrics(cve):
    """Escolhe a métrica exibida e a severidade usada nos filtros.

    Exibe a primeira versão presente na ordem 3.1 > 3.0 > 4.0 > 2.0 e, dentro dela, a nota da
    NVD (Primary) quando existir. O filtro usa `rank`: a maior severidade entre todas as notas
    3.x e 4.0 de qualquer fonte, para não esconder um CVE que a CNA classifica acima da NVD.
    Só sem nota 3.x/4.0 a v2 entra no filtro.
    """
    metrics = cve.get("metrics") or {}
    chosen = None
    modern = []
    legacy = []
    for field, label in METRIC_ORDER:
        fields = [_metric_fields(e, label) for e in metrics.get(field) or []]
        if not fields:
            continue
        if chosen is None:
            primary = [f for f in fields if (f["type"] or "").lower() == "primary"]
            chosen = primary[0] if primary else fields[0]
        (legacy if label == "2.0" else modern).extend(fields)
    if chosen is None:
        return {"version": None, "score": None, "severity": "", "vector": None,
                "source": None, "type": None, "rank": 0}
    pool = modern or legacy
    result = dict(chosen)
    result["rank"] = max(SEVERITY_RANK.get(f["severity"], 0) for f in pool)
    return result


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


def extract_kev(cve):
    """Data em que o CVE entrou no catálogo KEV da CISA, ou None."""
    return cve.get("cisaExploitAdd") or None


_CPE_SPLIT = re.compile(r"(?<!\\):")
_CPE_UNESCAPE = re.compile(r"\\(.)")


def _cpe_part(parts, index):
    if len(parts) <= index:
        return None
    return _CPE_UNESCAPE.sub(r"\1", parts[index])


def extract_cpes(cve):
    """Uma linha por cpeMatch. O mesmo `criteria` aparece várias vezes com faixas de versão
    diferentes (o Log4Shell tem três), por isso a chave é o `matchCriteriaId`, nunca o
    `criteria`. `vulnerable` é 0 para CPE de plataforma numa configuração AND."""
    rows = []
    seen = set()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                if not criteria:
                    continue
                vulnerable = 1 if match.get("vulnerable", True) else 0
                vstart = vstart_op = vend = vend_op = None
                if match.get("versionStartIncluding"):
                    vstart, vstart_op = match["versionStartIncluding"], ">="
                elif match.get("versionStartExcluding"):
                    vstart, vstart_op = match["versionStartExcluding"], ">"
                if match.get("versionEndIncluding"):
                    vend, vend_op = match["versionEndIncluding"], "<="
                elif match.get("versionEndExcluding"):
                    vend, vend_op = match["versionEndExcluding"], "<"
                match_id = match.get("matchCriteriaId") or ""
                key = (match_id, vulnerable) if match_id else (criteria, vulnerable, vstart, vend)
                if key in seen:
                    continue
                seen.add(key)
                parts = _CPE_SPLIT.split(criteria)
                vendor, product = _cpe_part(parts, 3), _cpe_part(parts, 4)
                rows.append({
                    "match_id": match_id or None,
                    "criteria": criteria,
                    "vendor_product": ("%s:%s" % (vendor, product)).lower() if product else "",
                    "cpe_version": _cpe_part(parts, 5),
                    "cpe_update": _cpe_part(parts, 6),
                    "target_sw": _cpe_part(parts, 10),
                    "vulnerable": vulnerable,
                    "version_start": vstart,
                    "version_start_op": vstart_op,
                    "version_end": vend,
                    "version_end_op": vend_op,
                })
    return rows


def upsert_cve(conn, cve, store_raw=True):
    """Grava ou atualiza um CVE. Com `store_raw=False` o JSON bruto já gravado é preservado."""
    cve_id = cve.get("id")
    if not cve_id:
        return 0
    metric = extract_metrics(cve)
    description = extract_description(cve)
    conn.execute(
        "INSERT INTO cves (cve_id, published, last_modified, vuln_status, description,"
        " description_lc, cvss_version, base_score, base_severity, severity_rank,"
        " vector_string, cwes, raw, cvss_source, cvss_type, kev_added)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(cve_id) DO UPDATE SET"
        " published=excluded.published, last_modified=excluded.last_modified,"
        " vuln_status=excluded.vuln_status, description=excluded.description,"
        " description_lc=excluded.description_lc, cvss_version=excluded.cvss_version,"
        " base_score=excluded.base_score, base_severity=excluded.base_severity,"
        " severity_rank=excluded.severity_rank, vector_string=excluded.vector_string,"
        " cwes=excluded.cwes, raw=COALESCE(excluded.raw, cves.raw),"
        " cvss_source=excluded.cvss_source, cvss_type=excluded.cvss_type,"
        " kev_added=excluded.kev_added",
        (
            cve_id,
            cve.get("published"),
            cve.get("lastModified"),
            cve.get("vulnStatus"),
            description,
            description.lower(),
            metric["version"],
            metric["score"],
            metric["severity"],
            metric["rank"],
            metric["vector"],
            extract_cwes(cve),
            json.dumps(cve, separators=(",", ":")) if store_raw else None,
            metric["source"],
            metric["type"],
            extract_kev(cve),
        ),
    )
    conn.execute("DELETE FROM cpes WHERE cve_id = ?", (cve_id,))
    rows = extract_cpes(cve)
    if rows:
        conn.executemany(
            "INSERT INTO cpes (cve_id, criteria, vendor_product, version_start, version_start_op,"
            " version_end, version_end_op, match_id, vulnerable, cpe_version, cpe_update,"
            " target_sw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (cve_id, r["criteria"], r["vendor_product"], r["version_start"],
                 r["version_start_op"], r["version_end"], r["version_end_op"], r["match_id"],
                 r["vulnerable"], r["cpe_version"], r["cpe_update"], r["target_sw"])
                for r in rows
            ],
        )
    return 1


# ---------------------------------------------------------------- busca por termo

_SEPARATORS = "-_. "


def escape_like(texto):
    """Escapa texto para um LIKE com ESCAPE '\\': tudo literal."""
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def keyword_like_core(keyword):
    """Termo como padrão LIKE (ESCAPE '\\'), sem os % das pontas. Separadores (`-`, `_`, `.`,
    espaço) viram curinga de um caractere, para `python-jose` casar `python_jose`; `%` e `\\`
    ficam literais."""
    out = []
    for ch in keyword.lower():
        if ch in _SEPARATORS:
            out.append("_")
        elif ch in "%\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def keyword_regex(keyword):
    """Casa o termo como palavra: não pode vir colado a letra, dígito ou `_` antes, nem a
    letra ou `_` depois. Assim `ws` casa "ws is" e não casa "allows", "Windows" nem "WS_FTP";
    `log4j` ainda casa "Log4j2"."""
    partes = [p for p in re.split(r"[-_. ]+", keyword.lower()) if p]
    corpo = r"[\W_]".join(re.escape(p) for p in partes)
    return re.compile(r"(?<![a-z0-9_])" + corpo + r"(?![a-z_])", re.IGNORECASE)


def min_rank(name):
    if not name:
        return 0
    rank = SEVERITY_RANK.get(name.upper())
    if rank is None:
        raise ValueError("severidade inválida %r; use LOW, MEDIUM, HIGH ou CRITICAL" % name)
    return rank


# ---------------------------------------------------------------- formatação

def _get(row, key, default=None):
    try:
        return row[key]
    except (IndexError, KeyError):
        return default


def format_cve(row, width=100):
    score = _get(row, "base_score")
    severity = _get(row, "base_severity") or ""
    rank = _get(row, "severity_rank") or 0
    if score is None and not severity:
        head = "%s  SEM NOTA (%s)" % (row["cve_id"], _get(row, "vuln_status") or "sem status")
    else:
        fonte = _get(row, "cvss_source")
        head = "%s  %s  %s (CVSS %s%s)" % (
            row["cve_id"],
            "n/d" if score is None else "%.1f" % score,
            severity or "n/d",
            _get(row, "cvss_version") or "n/d",
            (", " + fonte) if fonte else "",
        )
        if rank > SEVERITY_RANK.get(severity, 0):
            head += "  · outra fonte classifica como %s" % RANK_NAME[rank]
    status = _get(row, "vuln_status")
    if status == "Rejected":
        head += "  [REJEITADO]"
    desc = (_get(row, "description") or "").replace("\n", " ").strip()
    if width and len(desc) > width:
        desc = desc[: width - 1] + "…"
    lines = [head, "  " + desc]
    if _get(row, "cwes"):
        lines.append("  CWE: %s" % row["cwes"])
    if _get(row, "kev_added"):
        lines.append("  KEV: explorado ativamente, no catálogo da CISA desde %s" % row["kev_added"])
    return "\n".join(lines)
