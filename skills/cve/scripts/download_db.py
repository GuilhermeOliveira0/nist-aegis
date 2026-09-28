#!/usr/bin/env python3
"""Baixa a base de CVEs da NVD para um SQLite local, com retomada por checkpoint.

Uso:
    python download_db.py --db ~/.nvd/nvd.sqlite            # download completo
    python download_db.py --db ~/.nvd/nvd.sqlite --update   # incremental
    python download_db.py --db ~/.nvd/nvd.sqlite --reindex  # reprocessa o JSON já gravado

O download completo é paginado de 2000 em 2000. Cada página é gravada e o índice registrado
em `meta.checkpoint_index`, então um comando interrompido por timeout, queda de rede ou erro
da API retoma de onde parou quando reexecutado. A base só é marcada como completa quando a
paginação chega ao total informado pela NVD.

`--reindex` não usa a rede: reaplica a extração atual (CVSS 4.0, KEV, faixas de versão por
`matchCriteriaId`) sobre o JSON bruto já gravado. É o caminho para atualizar uma base criada
por uma versão anterior deste script sem baixar tudo de novo.

A chave da NVD é lida de NVD_API_KEY e nunca é impressa. Sem chave o rate limit cai de 50
para 5 requisições por 30 s.

Códigos de saída: 0 concluído, 2 argumento inválido, 3 erro de execução, 130 interrompido.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nvd_common import (  # noqa: E402
    DATA_VERSION,
    EXIT_ERROR,
    EXIT_OK,
    PAGE_SIZE,
    SLEEP_NO_KEY,
    SLEEP_WITH_KEY,
    NvdRequestError,
    api_key,
    configure_stdio,
    connect,
    db_path,
    init_schema,
    meta_get,
    meta_set,
    request_json,
    upsert_cve,
)

MAX_WINDOW_DAYS = 120  # limite da NVD para lastModStartDate/lastModEndDate
STAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


def now_utc():
    return datetime.now(timezone.utc)


def stamp(dt):
    return dt.strftime(STAMP_FORMAT)


def parse_stamp(texto):
    return datetime.strptime(texto, STAMP_FORMAT).replace(tzinfo=timezone.utc)


def store_page(conn, payload, store_raw):
    written = 0
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        written += upsert_cve(conn, cve, store_raw=store_raw)
    return written


def run_pages(conn, base_params, key, store_raw, label, resume_index=0):
    """Pagina uma consulta inteira, gravando checkpoint a cada página.

    Página vazia ou curta antes do total é erro: a paginação da NVD só encurta na última
    página. O checkpoint fica gravado e reexecutar o comando retoma dali.
    """
    sleep_for = SLEEP_WITH_KEY if key else SLEEP_NO_KEY
    start = resume_index
    total = None
    written = 0
    while True:
        params = dict(base_params)
        params["resultsPerPage"] = PAGE_SIZE
        params["startIndex"] = start
        payload = request_json(params, key)
        if total is None:
            total = int(payload.get("totalResults", 0) or 0)
            print("%s: %d CVEs a processar" % (label, total), flush=True)
        items = payload.get("vulnerabilities") or []
        got = len(items)
        written += store_page(conn, payload, store_raw)
        start += got
        meta_set(conn, "checkpoint_index", start)
        meta_set(conn, "checkpoint_total", total)
        conn.commit()
        pct = (min(start, total) / total * 100) if total else 100.0
        print("  %s  %d/%d (%.1f%%)" % (label, min(start, total), total, pct), flush=True)
        if start >= total:
            break
        if got < PAGE_SIZE:
            raise NvdRequestError(
                "a NVD devolveu %d registro(s) no índice %d, antes do fim (%d de %d): a paginação "
                "parou no meio; rode o mesmo comando para retomar do checkpoint"
                % (got, start - got, start, total)
            )
        time.sleep(sleep_for)
    return written


def full_download(conn, key, store_raw):
    # O checkpoint só vale para retomar um download completo interrompido. Base já marcada como
    # completa recomeça do zero: honrar um índice antigo pularia os primeiros registros.
    started = now_utc()
    resume = 0
    if meta_get(conn, "complete") != "1":
        resume = int(meta_get(conn, "checkpoint_index", "0") or 0)
    if resume:
        pendente = meta_get(conn, "sync_started")
        if pendente:
            started = parse_stamp(pendente)
        print("retomando do checkpoint: índice %d" % resume, flush=True)
    else:
        # O last_sync final é a hora de INÍCIO: o que a NVD alterar durante o download entra no
        # próximo --update, em vez de se perder entre páginas já baixadas.
        meta_set(conn, "sync_started", stamp(started))
        meta_set(conn, "complete", "0")
        conn.commit()
    written = run_pages(conn, {}, key, store_raw, "download", resume_index=resume)
    meta_set(conn, "complete", "1")
    meta_set(conn, "checkpoint_index", "0")
    meta_set(conn, "last_sync", stamp(started))
    meta_set(conn, "data_version", DATA_VERSION)
    conn.commit()
    return written


def incremental(conn, key, store_raw):
    last = meta_get(conn, "last_sync")
    if not last:
        raise NvdRequestError("base sem last_sync: rode o download completo antes do --update")
    start = parse_stamp(last)
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
    versao = int(meta_get(conn, "data_version", "1") or 1)
    if versao < DATA_VERSION:
        print("aviso: os CVEs não alterados ainda estão no formato de dados %d; rode --reindex "
              "para aplicar a extração atual a toda a base" % versao, flush=True)
    return written


def reindex(conn, batch=2000):
    """Reaplica a extração atual sobre o JSON bruto gravado, em lotes retomáveis."""
    last_rowid = int(meta_get(conn, "reindex_rowid", "0") or 0)
    total = conn.execute("SELECT COUNT(*) FROM cves WHERE raw IS NOT NULL").fetchone()[0]
    sem_raw = conn.execute("SELECT COUNT(*) FROM cves WHERE raw IS NULL").fetchone()[0]
    if last_rowid:
        print("retomando o reindex a partir do rowid %d" % last_rowid, flush=True)
    processed = 0
    while True:
        rows = conn.execute(
            "SELECT rowid, raw FROM cves WHERE rowid > ? AND raw IS NOT NULL ORDER BY rowid LIMIT ?",
            (last_rowid, batch),
        ).fetchall()
        if not rows:
            break
        for row in rows:
            upsert_cve(conn, json.loads(row["raw"]), store_raw=False)
            last_rowid = row["rowid"]
        meta_set(conn, "reindex_rowid", last_rowid)
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        processed += len(rows)
        print("  reindex  %d/%d" % (processed, total), flush=True)
    meta_set(conn, "reindex_rowid", "0")
    meta_set(conn, "data_version", DATA_VERSION)
    conn.commit()
    if sem_raw:
        print("aviso: %d CVE(s) sem JSON bruto (baixados com --skip-raw) ficaram como estavam; só "
              "um download completo atualiza esses" % sem_raw, flush=True)
    return processed


def build_parser():
    parser = argparse.ArgumentParser(description="Baixa a base de CVEs da NVD para SQLite.")
    parser.add_argument("--db", required=True, help="caminho do arquivo SQLite")
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument("--update", action="store_true", help="sincronização incremental")
    modo.add_argument("--reindex", action="store_true",
                      help="reprocessa o JSON bruto já gravado, sem rede")
    parser.add_argument(
        "--skip-raw",
        action="store_true",
        help="não guarda o JSON bruto de cada CVE (base bem menor, mas sem --reindex futuro)",
    )
    return parser


def main(argv=None):
    configure_stdio()
    args = build_parser().parse_args(argv)
    resolved = db_path(args.db)
    existed = os.path.exists(resolved)

    key = None
    if not args.reindex:
        key = api_key()
        print("chave NVD_API_KEY: %s" % ("presente" if key else "ausente (modo limitado)"), flush=True)
        if not key:
            print("  sem chave o rate limit é 5 req/30s: o download completo fica bem mais lento",
                  flush=True)

    if (args.update or args.reindex) and not existed:
        print("ERRO: %s exige base existente em %s" % ("--update" if args.update else "--reindex",
                                                        resolved), file=sys.stderr)
        return EXIT_ERROR

    try:
        conn = connect(resolved)
        init_schema(conn)
    except sqlite3.Error as exc:
        print("ERRO: não foi possível abrir a base: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    started = time.time()
    try:
        if args.reindex:
            written = reindex(conn)
        elif args.update:
            written = incremental(conn, key, not args.skip_raw)
        else:
            written = full_download(conn, key, not args.skip_raw)
    except KeyboardInterrupt:
        conn.commit()
        print("\ninterrompido — o checkpoint foi salvo, rode o mesmo comando para retomar")
        return 130
    except NvdRequestError as exc:
        conn.commit()
        print("ERRO: %s" % exc, file=sys.stderr)
        print("a base NÃO foi marcada como completa; o checkpoint foi salvo", file=sys.stderr)
        return EXIT_ERROR
    except sqlite3.Error as exc:
        print("ERRO: falha ao gravar na base: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    total = conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"]
    conn.commit()
    conn.close()
    size_mb = os.path.getsize(resolved) / (1024 * 1024)
    print(
        "concluído: %d CVEs %s nesta execução, %d na base, %.0f MB, %.0f s"
        % (written, "reprocessados" if args.reindex else "gravados", total, size_mb,
           time.time() - started)
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
