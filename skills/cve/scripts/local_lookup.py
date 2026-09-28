#!/usr/bin/env python3
"""Consulta a base local de CVEs da NVD.

Uso:
    python local_lookup.py --db ~/.nvd/nvd.sqlite --stats
    python local_lookup.py --db ~/.nvd/nvd.sqlite --cve CVE-2021-44228
    python local_lookup.py --db ~/.nvd/nvd.sqlite --keyword lodash --min-severity HIGH --limit 3
    python local_lookup.py --db ~/.nvd/nvd.sqlite --product microsoft:windows --min-severity CRITICAL --limit 3

Não faz rede e não lê NVD_API_KEY.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nvd_common import (  # noqa: E402
    SEVERITY_RANK,
    connect,
    db_path,
    format_cve,
    meta_get,
    min_rank,
)

SYNC_STALE_DAYS = 7
COLUMNS = (
    "cve_id, published, last_modified, description, cvss_version,"
    " base_score, base_severity, severity_rank, vector_string, cwes"
)


def show_stats(conn, resolved, as_json):
    total = conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"]
    by_sev = {
        row["base_severity"] or "SEM_SCORE": row["n"]
        for row in conn.execute(
            "SELECT base_severity, COUNT(*) AS n FROM cves GROUP BY base_severity"
        )
    }
    last_sync = meta_get(conn, "last_sync")
    complete = meta_get(conn, "complete") == "1"
    checkpoint = int(meta_get(conn, "checkpoint_index", "0") or 0)
    stale = None
    if last_sync:
        synced = datetime.strptime(last_sync, "%Y-%m-%dT%H:%M:%S.000Z").replace(
            tzinfo=timezone.utc
        )
        stale = (datetime.now(timezone.utc) - synced) > timedelta(days=SYNC_STALE_DAYS)
    size_mb = os.path.getsize(resolved) / (1024 * 1024) if os.path.exists(resolved) else 0

    if as_json:
        print(
            json.dumps(
                {
                    "db": resolved,
                    "total_cves": total,
                    "por_severidade": by_sev,
                    "last_sync": last_sync,
                    "sync_desatualizado": stale,
                    "completa": complete,
                    "checkpoint_pendente": checkpoint,
                    "tamanho_mb": round(size_mb, 1),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    print("base:            %s" % resolved)
    print("total de CVEs:   %d" % total)
    print("tamanho:         %.0f MB" % size_mb)
    print("último sync:     %s" % (last_sync or "nunca"))
    if stale is not None:
        print(
            "estado do sync:  %s"
            % ("DESATUALIZADO (mais de %d dias)" % SYNC_STALE_DAYS if stale else "recente")
        )
    print("base completa:   %s" % ("sim" if complete else "NÃO"))
    if checkpoint:
        print("checkpoint:      download pendente a partir do índice %d" % checkpoint)
    print("por severidade:")
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SEM_SCORE"):
        if name in by_sev:
            print("  %-9s %d" % (name, by_sev[name]))


def query_rows(conn, args):
    rank = min_rank(args.min_severity)
    if args.cve:
        sql = "SELECT %s FROM cves WHERE cve_id = ? COLLATE NOCASE" % COLUMNS
        return conn.execute(sql, (args.cve,)).fetchall()

    where = []
    params = []
    if args.keyword:
        needle = "%" + args.keyword.lower() + "%"
        where.append(
            "(description_lc LIKE ?"
            " OR EXISTS (SELECT 1 FROM cpes WHERE cpes.cve_id = cves.cve_id"
            "            AND cpes.vendor_product LIKE ?))"
        )
        params.extend([needle, needle])
    if args.product:
        where.append(
            "EXISTS (SELECT 1 FROM cpes WHERE cpes.cve_id = cves.cve_id"
            "        AND cpes.vendor_product LIKE ?)"
        )
        params.append(args.product.lower() + "%")
    if rank:
        where.append("severity_rank >= ?")
        params.append(rank)
    if not where:
        sys.exit("ERRO: informe --stats, --cve, --keyword ou --product.")

    sql = "SELECT %s FROM cves WHERE %s ORDER BY base_score DESC, cve_id ASC LIMIT ?" % (
        COLUMNS,
        " AND ".join(where),
    )
    params.append(args.limit)
    return conn.execute(sql, params).fetchall()


def main():
    parser = argparse.ArgumentParser(description="Consulta a base local de CVEs da NVD.")
    parser.add_argument("--db", required=True, help="caminho do arquivo SQLite")
    parser.add_argument("--stats", action="store_true", help="estado da base")
    parser.add_argument("--cve", help="consulta um CVE por identificador")
    parser.add_argument("--keyword", help="busca por termo na descrição e nos CPEs")
    parser.add_argument("--product", help="busca por vendor:product do CPE, ex.: microsoft:windows")
    parser.add_argument(
        "--min-severity",
        choices=sorted(SEVERITY_RANK, key=SEVERITY_RANK.get),
        help="severidade mínima",
    )
    parser.add_argument("--limit", type=int, default=20, help="máximo de resultados")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    args = parser.parse_args()

    resolved = db_path(args.db)
    conn = connect(resolved, create=False)

    if args.stats:
        show_stats(conn, resolved, args.json)
        return 0

    rows = query_rows(conn, args)
    if args.json:
        print(json.dumps([dict(row) for row in rows], ensure_ascii=False, indent=2))
        return 0 if rows else 1

    if not rows:
        print("nenhum CVE encontrado para os critérios informados")
        return 1
    for row in rows:
        print(format_cve(row))
        print()
    print("%d resultado(s)" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
