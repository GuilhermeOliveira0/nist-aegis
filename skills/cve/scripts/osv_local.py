"""Espelho local do OSV em SQLite: importação dos arquivos publicados e consulta por pacote.

A consulta não faz rede: casa nome e ecossistema no índice e decide a versão com os comparadores
de osv_versions.py. O registro devolvido tem o mesmo formato do registro da API do OSV (id,
aliases, summary, details, severity, database_specific, withdrawn, affected), só com as entradas
`affected` do pacote consultado, para que o sca_scan monte o resultado do mesmo jeito nos dois
modos.

Só biblioteca padrão.
"""

import json
import os
import pathlib
import re
import sqlite3
import zipfile
from datetime import datetime, timezone

import osv_versions as ov

SCHEMA_VERSION = 1
ECOSSISTEMAS = ("npm", "PyPI", "Go", "Maven", "crates.io", "Packagist", "RubyGems", "NuGet")
MAX_REGISTRO_BYTES = 20 * 1024 * 1024
DETALHES_MAX = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS vulns (
    id                TEXT PRIMARY KEY,
    modified          TEXT,
    withdrawn         TEXT,
    summary           TEXT,
    details           TEXT,
    aliases           TEXT,
    severity          TEXT,
    database_specific TEXT
);
CREATE TABLE IF NOT EXISTS affected (
    vuln_id   TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name_key  TEXT NOT NULL,
    name      TEXT,
    ranges    TEXT,
    versions  TEXT
);
CREATE INDEX IF NOT EXISTS affected_pacote ON affected (ecosystem, name_key);
CREATE INDEX IF NOT EXISTS affected_vuln ON affected (vuln_id, ecosystem);
"""


class BaseOsvErro(RuntimeError):
    pass


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def name_key(ecosystem, name):
    """Chave de busca: PyPI pela PEP 503; Go e Maven como publicados; o resto sem caixa."""
    name = name or ""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("Go", "Maven", "RubyGems"):
        return name
    return name.lower()


# ---------------------------------------------------------------- conexão e meta

def connect(path, create=False, readonly=False):
    path = os.path.abspath(os.path.expanduser(path))
    if not create and not os.path.exists(path):
        raise FileNotFoundError("base OSV local não encontrada em %s — rode download_osv.py" % path)
    if readonly:
        conn = sqlite3.connect(pathlib.Path(path).as_uri() + "?mode=ro", uri=True)
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # transação explícita (BEGIN ... COMMIT): a importação de um ecossistema é tudo ou nada
        conn = sqlite3.connect(path, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn):
    conn.executescript(SCHEMA)
    meta_set(conn, "schema_version", SCHEMA_VERSION)
    conn.commit()


def meta_get(conn, key, default=None):
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    except sqlite3.OperationalError:
        return default
    return row["value"] if row else default


def meta_set(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))


# ---------------------------------------------------------------- importação

def _json_curto(valor):
    return json.dumps(valor, ensure_ascii=False, separators=(",", ":")) if valor else None


def importar_registro(conn, registro, ecossistema):
    """Grava um registro OSV. Só as entradas `affected` do ecossistema do arquivo de origem
    entram, para que o mesmo aviso publicado em dois ecossistemas não se duplique."""
    if not isinstance(registro, dict) or not isinstance(registro.get("id"), str):
        return False
    vid = registro["id"]
    db_spec = registro.get("database_specific") or {}
    db_spec = {k: db_spec[k] for k in ("severity", "cwe_ids") if isinstance(db_spec, dict) and k in db_spec}
    detalhes = registro.get("details")
    conn.execute(
        "INSERT INTO vulns (id, modified, withdrawn, summary, details, aliases, severity, database_specific)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET modified = excluded.modified,"
        " withdrawn = excluded.withdrawn, summary = excluded.summary, details = excluded.details,"
        " aliases = excluded.aliases, severity = excluded.severity,"
        " database_specific = excluded.database_specific",
        (vid, registro.get("modified"), registro.get("withdrawn"), registro.get("summary"),
         detalhes[:DETALHES_MAX] if isinstance(detalhes, str) else None,
         _json_curto(registro.get("aliases")), _json_curto(registro.get("severity")), _json_curto(db_spec)))
    conn.execute("DELETE FROM affected WHERE vuln_id = ? AND ecosystem = ?", (vid, ecossistema))
    for aff in registro.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        if pkg.get("ecosystem") != ecossistema or not isinstance(pkg.get("name"), str):
            continue
        conn.execute(
            "INSERT INTO affected (vuln_id, ecosystem, name_key, name, ranges, versions) VALUES (?, ?, ?, ?, ?, ?)",
            (vid, ecossistema, name_key(ecossistema, pkg["name"]), pkg["name"],
             _json_curto(aff.get("ranges")), _json_curto(aff.get("versions"))))
    return True


def importar_zip(conn, ecossistema, caminho_zip):
    """Troca todo o conteúdo do ecossistema pelo do arquivo. Numa transação: se algo falhar no
    meio, a base fica como estava."""
    total = 0
    try:
        with zipfile.ZipFile(caminho_zip) as zf:
            conn.execute("BEGIN")
            conn.execute("DELETE FROM affected WHERE ecosystem = ?", (ecossistema,))
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".json") or info.file_size > MAX_REGISTRO_BYTES:
                    continue
                try:
                    registro = json.loads(zf.read(info).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if importar_registro(conn, registro, ecossistema):
                    total += 1
            limpar_orfaos(conn)
            conn.commit()
    except (zipfile.BadZipFile, sqlite3.Error, OSError) as exc:
        conn.rollback()
        raise BaseOsvErro("importação de %s falhou: %s" % (ecossistema, exc))
    return total


def limpar_orfaos(conn):
    conn.execute("DELETE FROM vulns WHERE id NOT IN (SELECT DISTINCT vuln_id FROM affected)")


# ---------------------------------------------------------------- consulta

class BaseOsvLocal:
    """Consulta só leitura. `consultar` devolve (registros afetados, ids não avaliados)."""

    def __init__(self, path):
        self.path = os.path.abspath(os.path.expanduser(path))
        self.conn = connect(self.path, readonly=True)

    def estado(self, agora=None):
        agora = agora or datetime.now(timezone.utc)
        por_eco = {}
        for eco in ECOSSISTEMAS:
            importado = meta_get(self.conn, "eco:%s:atualizado_em" % eco)
            if not importado:
                continue
            try:
                idade = (agora - datetime.strptime(importado, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)).total_seconds() / 86400
            except ValueError:
                idade = None
            por_eco[eco] = {"atualizado_em": importado, "idade_dias": None if idade is None else round(idade, 1),
                            "registros": int(meta_get(self.conn, "eco:%s:registros" % eco, "0") or 0)}
        return {"caminho": self.path, "estado": "disponível" if por_eco else "vazia", "ecossistemas": por_eco}

    def consultar(self, ecossistema, nome, versao):
        rows = self.conn.execute(
            "SELECT a.vuln_id, a.name, a.ranges, a.versions, v.modified, v.withdrawn, v.summary, v.details,"
            " v.aliases, v.severity, v.database_specific FROM affected a JOIN vulns v ON v.id = a.vuln_id"
            " WHERE a.ecosystem = ? AND a.name_key = ? ORDER BY a.vuln_id",
            (ecossistema, name_key(ecossistema, nome))).fetchall()
        registros = {}
        nao_avaliados = []
        for row in rows:
            entrada = {"package": {"ecosystem": ecossistema, "name": row["name"]},
                       "ranges": json.loads(row["ranges"]) if row["ranges"] else [],
                       "versions": json.loads(row["versions"]) if row["versions"] else []}
            resultado = ov.is_affected(ecossistema, versao, entrada)
            if resultado is None:
                if row["vuln_id"] not in nao_avaliados:
                    nao_avaliados.append(row["vuln_id"])
                continue
            if not resultado:
                continue
            reg = registros.get(row["vuln_id"])
            if reg is None:
                reg = registros[row["vuln_id"]] = {
                    "id": row["vuln_id"], "modified": row["modified"], "withdrawn": row["withdrawn"],
                    "summary": row["summary"], "details": row["details"],
                    "aliases": json.loads(row["aliases"]) if row["aliases"] else [],
                    "severity": json.loads(row["severity"]) if row["severity"] else [],
                    "database_specific": json.loads(row["database_specific"]) if row["database_specific"] else {},
                    "affected": [],
                }
            reg["affected"].append(entrada)
        # afetado por uma entrada decide, mesmo que outra do mesmo aviso não seja avaliável
        nao_avaliados = [v for v in nao_avaliados if v not in registros]
        return list(registros.values()), nao_avaliados

    def close(self):
        self.conn.close()
