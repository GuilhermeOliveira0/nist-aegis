#!/usr/bin/env python3
"""Consulta a base local de CVEs da NVD.

Uso:
    python local_lookup.py --db ~/.nvd/nvd.sqlite --stats
    python local_lookup.py --db ~/.nvd/nvd.sqlite --cve CVE-2021-44228
    python local_lookup.py --db ~/.nvd/nvd.sqlite --keyword lodash --min-severity HIGH --limit 3
    python local_lookup.py --db ~/.nvd/nvd.sqlite --product microsoft:windows --min-severity CRITICAL --limit 3

Não faz rede, não lê NVD_API_KEY e abre a base só para leitura.

Códigos de saída: 0 com resultado, 1 sem resultado, 2 argumento inválido, 3 erro de execução.
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nvd_common as nc  # noqa: E402

SYNC_STALE_DAYS = 7
BASE_COLUMNS = (
    "cve_id", "published", "last_modified", "vuln_status", "description", "cvss_version",
    "base_score", "base_severity", "severity_rank", "vector_string", "cwes",
)
OPTIONAL_COLUMNS = ("cvss_source", "cvss_type", "kev_added")
CPE_COLUMNS = (
    "vendor_product", "criteria", "vulnerable", "cpe_version", "cpe_update", "target_sw",
    "version_start", "version_start_op", "version_end", "version_end_op",
)


class UsageError(Exception):
    """Combinação de argumentos que não forma uma consulta."""


def build_parser():
    parser = argparse.ArgumentParser(description="Consulta a base local de CVEs da NVD.")
    parser.add_argument("--db", required=True, help="caminho do arquivo SQLite")
    parser.add_argument("--stats", action="store_true", help="estado da base")
    parser.add_argument("--cve", help="consulta um CVE por identificador")
    parser.add_argument(
        "--keyword",
        help="termo como palavra inteira na descrição, ou como vendor/produto de CPE",
    )
    parser.add_argument("--product", help="prefixo de vendor:product do CPE, ex.: microsoft:windows")
    parser.add_argument("--min-severity", choices=nc.SEVERITY_CHOICES, help="severidade mínima")
    parser.add_argument("--limit", type=nc.positive_int(100000), default=20, help="máximo de resultados")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    parser.add_argument("--detalhes", action="store_true", help="descrição inteira e faixas de versão")
    parser.add_argument("--incluir-rejeitados", action="store_true", help="inclui CVEs com status Rejected")
    parser.add_argument(
        "--excluir-sem-nota", action="store_true",
        help="com --min-severity, descarta CVE sem nota (por padrão ele aparece marcado)",
    )
    parser.add_argument(
        "--incluir-plataforma", action="store_true",
        help="conta também CPE marcado vulnerable:false (plataforma numa configuração AND)",
    )
    return parser


# ---------------------------------------------------------------- estado da base

def sync_state(conn, total):
    last_sync = nc.meta_get(conn, "last_sync")
    complete = nc.meta_get(conn, "complete") == "1"
    stale = None
    if last_sync:
        try:
            synced = datetime.strptime(last_sync, "%Y-%m-%dT%H:%M:%S.000Z").replace(tzinfo=timezone.utc)
            stale = (datetime.now(timezone.utc) - synced) > timedelta(days=SYNC_STALE_DAYS)
        except ValueError:
            stale = True
    if total == 0:
        estado = "VAZIA — rode download_db.py"
    elif not complete:
        estado = ("INCOMPLETA — download interrompido ou não concluído; rode o mesmo comando de "
                  "download para retomar")
    elif not last_sync:
        estado = "NUNCA SINCRONIZADA"
    elif stale:
        estado = "DESATUALIZADO (mais de %d dias)" % SYNC_STALE_DAYS
    else:
        estado = "recente"
    return last_sync, complete, stale, estado


def show_stats(conn, resolved, as_json):
    total = conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"]
    by_sev = {
        row["base_severity"] or "SEM_SCORE": row["n"]
        for row in conn.execute("SELECT base_severity, COUNT(*) AS n FROM cves GROUP BY base_severity")
    }
    rejeitados = conn.execute(
        "SELECT COUNT(*) AS n FROM cves WHERE vuln_status = 'Rejected'").fetchone()["n"]
    sem_nota = conn.execute(
        "SELECT COUNT(*) AS n FROM cves WHERE COALESCE(severity_rank, 0) = 0"
        " AND COALESCE(vuln_status, '') <> 'Rejected'").fetchone()["n"]
    no_kev = None
    if "kev_added" in nc.table_columns(conn, "cves"):
        no_kev = conn.execute("SELECT COUNT(*) AS n FROM cves WHERE kev_added IS NOT NULL").fetchone()["n"]
    last_sync, complete, stale, estado = sync_state(conn, total)
    checkpoint = int(nc.meta_get(conn, "checkpoint_index", "0") or 0)
    versao_dados = int(nc.meta_get(conn, "data_version", "1") or 1)
    precisa_reindex = versao_dados < nc.DATA_VERSION
    size_mb = os.path.getsize(resolved) / (1024 * 1024) if os.path.exists(resolved) else 0

    if as_json:
        print(json.dumps({
            "db": resolved,
            "total_cves": total,
            "por_severidade": by_sev,
            "rejeitados": rejeitados,
            "sem_nota_validos": sem_nota,
            "no_kev": no_kev,
            "last_sync": last_sync,
            "sync_desatualizado": stale,
            "completa": complete,
            "checkpoint_pendente": checkpoint if not complete else 0,
            "estado": estado,
            "versao_dados": versao_dados,
            "precisa_reindex": precisa_reindex,
            "tamanho_mb": round(size_mb, 1),
        }, ensure_ascii=False, indent=2))
        return

    print("base:            %s" % resolved)
    print("total de CVEs:   %d (%d rejeitados, %d válidos sem nota)" % (total, rejeitados, sem_nota))
    print("tamanho:         %.0f MB" % size_mb)
    print("último sync:     %s" % (last_sync or "nunca"))
    print("estado do sync:  %s" % estado)
    print("base completa:   %s" % ("sim" if complete else "NÃO"))
    if checkpoint and not complete:
        print("checkpoint:      download pendente a partir do índice %d" % checkpoint)
    if no_kev is not None:
        print("no KEV da CISA:  %d" % no_kev)
    if precisa_reindex:
        print("dados:           versão %d — rode download_db.py --reindex para ganhar CVSS 4.0,"
              " KEV e as faixas de versão completas" % versao_dados)
    print("por severidade:")
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SEM_SCORE"):
        if name in by_sev:
            print("  %-9s %d" % (name, by_sev[name]))


# ---------------------------------------------------------------- consulta

def _select_list(cols_cves):
    cols = list(BASE_COLUMNS) + [c for c in OPTIONAL_COLUMNS if c in cols_cves]
    return ", ".join("cves.%s" % c for c in cols)


def query_rows(conn, args):
    """Devolve (linhas até --limit, total que casou)."""
    cols_cves = nc.table_columns(conn, "cves")
    cols_cpes = nc.table_columns(conn, "cpes")
    select = _select_list(cols_cves)

    if args.cve:
        rows = conn.execute(
            "SELECT %s FROM cves WHERE cve_id = ? COLLATE NOCASE" % select, (args.cve.strip(),)
        ).fetchall()
        return rows, len(rows)
    if not (args.keyword or args.product or args.min_severity):
        raise UsageError("informe --stats, --cve, --keyword, --product ou --min-severity")

    where = []
    params = []
    if not args.incluir_rejeitados:
        where.append("COALESCE(cves.vuln_status, '') <> 'Rejected'")
    rank = nc.min_rank(args.min_severity)
    if rank:
        if args.excluir_sem_nota:
            where.append("cves.severity_rank >= ?")
        else:
            where.append("(cves.severity_rank >= ? OR COALESCE(cves.severity_rank, 0) = 0)")
        params.append(rank)

    vuln_sql = ""
    if "vulnerable" in cols_cpes and not args.incluir_plataforma:
        vuln_sql = " AND (cpes.vulnerable = 1 OR cpes.vulnerable IS NULL)"
    if args.product:
        where.append(
            "EXISTS (SELECT 1 FROM cpes WHERE cpes.cve_id = cves.cve_id%s"
            " AND cpes.vendor_product LIKE ? ESCAPE '\\')" % vuln_sql
        )
        params.append(nc.escape_like(args.product.strip().lower()) + "%")

    order = "cves.severity_rank DESC, cves.base_score DESC, cves.cve_id ASC"
    if not args.keyword:
        where_sql = " AND ".join(where)
        total = conn.execute("SELECT COUNT(*) FROM cves WHERE %s" % where_sql, params).fetchone()[0]
        rows = conn.execute(
            "SELECT %s FROM cves WHERE %s ORDER BY %s LIMIT ?" % (select, where_sql, order),
            params + [args.limit],
        ).fetchall()
        return rows, total

    # Termo: o LIKE pré-filtra no SQLite e a expressão regular exige palavra inteira na
    # descrição. Casamento exato de vendor ou produto no CPE entra direto.
    core = nc.keyword_like_core(args.keyword.strip())
    cpe_sql = (
        "EXISTS (SELECT 1 FROM cpes WHERE cpes.cve_id = cves.cve_id%s"
        " AND (cpes.vendor_product LIKE ? ESCAPE '\\' OR cpes.vendor_product LIKE ? ESCAPE '\\'))"
        % vuln_sql
    )
    cpe_params = ["%:" + core, core + ":%"]
    where.append("(cves.description_lc LIKE ? ESCAPE '\\' OR %s)" % cpe_sql)
    params.extend(["%" + core + "%"] + cpe_params)
    regex = nc.keyword_regex(args.keyword.strip())
    candidates = conn.execute(
        "SELECT %s, %s AS cpe_hit FROM cves WHERE %s" % (select, cpe_sql, " AND ".join(where)),
        cpe_params + params,
    ).fetchall()
    matched = [r for r in candidates if r["cpe_hit"] or regex.search(r["description"] or "")]
    matched.sort(key=lambda r: (-(r["severity_rank"] or 0), -(r["base_score"] or 0), r["cve_id"]))
    return matched[: args.limit], len(matched)


def cpe_rows(conn, cve_id):
    cols = [c for c in CPE_COLUMNS if c in nc.table_columns(conn, "cpes")]
    return [
        dict(r) for r in conn.execute(
            "SELECT %s FROM cpes WHERE cve_id = ?" % ", ".join(cols), (cve_id,))
    ]


def _faixa(cpe):
    partes = []
    if cpe.get("version_start"):
        partes.append("%s %s" % (cpe["version_start_op"], cpe["version_start"]))
    if cpe.get("version_end"):
        partes.append("%s %s" % (cpe["version_end_op"], cpe["version_end"]))
    if not partes:
        versao = cpe.get("cpe_version")
        update = cpe.get("cpe_update")
        if versao and versao not in ("*", "-"):
            return "= %s%s" % (versao, (" " + update) if update and update not in ("*", "-") else "")
        return "todas as versões" if versao == "*" else "versão não se aplica"
    return ", ".join(partes)


def print_rows(conn, rows, total, detalhes):
    for row in rows:
        print(nc.format_cve(row, width=None if detalhes else 100))
        if detalhes:
            for cpe in cpe_rows(conn, row["cve_id"]):
                marca = "" if cpe.get("vulnerable", 1) in (1, None) else "  (plataforma, não vulnerável)"
                print("  CPE: %s  %s%s" % (cpe["vendor_product"], _faixa(cpe), marca))
        print()
    if total > len(rows):
        print("mostrando %d de %d resultado(s) — aumente --limit para ver o resto" % (len(rows), total))
    else:
        print("%d resultado(s)" % len(rows))


def main(argv=None):
    nc.configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        conn = nc.connect(args.db, create=False, readonly=True)
    except FileNotFoundError as exc:
        print("ERRO: %s" % exc, file=sys.stderr)
        return nc.EXIT_ERROR
    except sqlite3.Error as exc:
        print("ERRO: não foi possível abrir a base: %s" % exc, file=sys.stderr)
        return nc.EXIT_ERROR
    try:
        if args.stats:
            show_stats(conn, nc.db_path(args.db), args.json)
            return nc.EXIT_OK
        try:
            rows, total = query_rows(conn, args)
        except UsageError as exc:
            parser.print_usage(sys.stderr)
            print("ERRO: %s" % exc, file=sys.stderr)
            return nc.EXIT_USAGE
        if args.json:
            resultados = []
            for row in rows:
                item = {k: row[k] for k in row.keys() if k != "cpe_hit"}
                item["cpes"] = cpe_rows(conn, row["cve_id"])
                resultados.append(item)
            print(json.dumps({"total": total, "mostrando": len(rows), "resultados": resultados},
                             ensure_ascii=False, indent=2))
            return nc.EXIT_OK if rows else nc.EXIT_NONE
        if not rows:
            print("nenhum CVE encontrado para os critérios informados")
            return nc.EXIT_NONE
        print_rows(conn, rows, total, args.detalhes)
        return nc.EXIT_OK
    except BrokenPipeError:
        nc.silence_broken_pipe()
        return nc.EXIT_OK
    except sqlite3.Error as exc:
        print("ERRO: a consulta falhou: %s" % exc, file=sys.stderr)
        return nc.EXIT_ERROR
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
