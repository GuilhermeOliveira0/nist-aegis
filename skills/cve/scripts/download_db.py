#!/usr/bin/env python3
"""Baixa a base de CVEs da NVD para um SQLite local, com retomada por checkpoint.

Uso:
    python download_db.py --db ~/.nvd/nvd.sqlite            # download completo
    python download_db.py --db ~/.nvd/nvd.sqlite --update   # incremental

O download completo é paginado de 2000 em 2000. Cada página é gravada e o
índice registrado em `meta.checkpoint_index`, então um comando interrompido por
timeout ou queda de rede retoma de onde parou quando reexecutado.

A chave da NVD é lida de NVD_API_KEY e nunca é impressa. Sem chave o rate limit
cai de 50 para 5 requisições por 30 s.
"""

import argparse
import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nvd_common import (  # noqa: E402
    PAGE_SIZE,
    SLEEP_NO_KEY,
    SLEEP_WITH_KEY,
    api_key,
    connect,
    db_path,
    init_schema,
    meta_get,
    meta_set,
    request_json,
    upsert_cve,
)

MAX_WINDOW_DAYS = 120  # limite da NVD para lastModStartDate/lastModEndDate


def now_utc():
    return datetime.now(timezone.utc)


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def store_page(conn, payload, store_raw):
    written = 0
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        written += upsert_cve(conn, cve, store_raw=store_raw)
    return written


def run_pages(conn, base_params, key, store_raw, label, resume_index=0):
    """Pagina uma consulta inteira, gravando checkpoint a cada página."""
    sleep_for = SLEEP_WITH_KEY if key else SLEEP_NO_KEY
    start = resume_index
    total = None
    written = 0
    while True:
        params = dict(base_params)
        params["resultsPerPage"] = PAGE_SIZE
        params["startIndex"] = start
        payload = request_json(params, key)
        if payload is None:
            break
        if total is None:
            total = payload.get("totalResults", 0)
            print("%s: %d CVEs a processar" % (label, total), flush=True)
        got = len(payload.get("vulnerabilities") or [])
        written += store_page(conn, payload, store_raw)
        start += PAGE_SIZE
        meta_set(conn, "checkpoint_index", start)
        meta_set(conn, "checkpoint_total", total or 0)
        conn.commit()
        pct = (min(start, total) / total * 100) if total else 100.0
        print(
            "  %s  %d/%d (%.1f%%)" % (label, min(start, total or start), total or 0, pct),
            flush=True,
        )
        if got < PAGE_SIZE or (total is not None and start >= total):
            break
        time.sleep(sleep_for)
    return written


def full_download(conn, key, store_raw):
    # Checkpoint só vale para retomar um download completo interrompido. Base já marcada
    # como completa recomeça do zero: honrar um índice antigo pularia os primeiros registros.
    resume = 0
    if meta_get(conn, "complete") != "1":
        resume = int(meta_get(conn, "checkpoint_index", "0") or 0)
    if resume:
        print("retomando do checkpoint: índice %d" % resume, flush=True)
    written = run_pages(conn, {}, key, store_raw, "download", resume_index=resume)
    meta_set(conn, "complete", "1")
    meta_set(conn, "checkpoint_index", "0")
    meta_set(conn, "last_sync", stamp(now_utc()))
    conn.commit()
    return written


def incremental(conn, key, store_raw):
    last = meta_get(conn, "last_sync")
    if not last:
        sys.exit("ERRO: base sem last_sync. Rode o download completo antes do --update.")
    start = datetime.strptime(last, "%Y-%m-%dT%H:%M:%S.000Z").replace(tzinfo=timezone.utc)
    end = now_utc()
    written = 0
    window = 0
    while start < end:
        chunk_end = min(start + timedelta(days=MAX_WINDOW_DAYS), end)
        window += 1
        written += run_pages(
            conn,
            {"lastModStartDate": stamp(start), "lastModEndDate": stamp(chunk_end)},
            key,
            store_raw,
            "janela %d" % window,
        )
        start = chunk_end
    meta_set(conn, "last_sync", stamp(end))
    # run_pages grava checkpoint a cada página, mas no incremental ele não serve para retomada:
    # o ponto de retomada é o last_sync. Zerar evita "download pendente" fantasma no --stats.
    meta_set(conn, "checkpoint_index", "0")
    meta_set(conn, "checkpoint_total", "0")
    conn.commit()
    return written


def main():
    parser = argparse.ArgumentParser(description="Baixa a base de CVEs da NVD para SQLite.")
    parser.add_argument("--db", required=True, help="caminho do arquivo SQLite")
    parser.add_argument("--update", action="store_true", help="sincronização incremental")
    parser.add_argument(
        "--skip-raw",
        action="store_true",
        help="não guarda o JSON bruto de cada CVE (base bem menor, sem perda para consulta)",
    )
    args = parser.parse_args()

    key = api_key()
    print("chave NVD_API_KEY: %s" % ("presente" if key else "ausente (modo limitado)"), flush=True)
    if not key:
        print(
            "  sem chave o rate limit é 5 req/30s: o download completo leva 15-20 minutos",
            flush=True,
        )

    resolved = db_path(args.db)
    existed = os.path.exists(resolved)
    conn = connect(resolved)
    init_schema(conn)

    started = time.time()
    try:
        if args.update:
            if not existed:
                sys.exit("ERRO: --update exige base existente em %s" % resolved)
            written = incremental(conn, key, not args.skip_raw)
        else:
            written = full_download(conn, key, not args.skip_raw)
    except KeyboardInterrupt:
        conn.commit()
        print("\ninterrompido — o checkpoint foi salvo, rode o mesmo comando para retomar")
        return 130

    total = conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"]
    conn.commit()
    conn.close()
    size_mb = os.path.getsize(resolved) / (1024 * 1024)
    print(
        "concluído: %d CVEs gravados nesta execução, %d na base, %.0f MB, %.0f s"
        % (written, total, size_mb, time.time() - started)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
