#!/usr/bin/env python3
"""Baixa a base de CVEs da NVD para um SQLite local, com retomada por checkpoint.

Uso:
    python download_db.py            # download completo
    python download_db.py --update   # incremental
    python download_db.py --reindex  # reprocessa o JSON já gravado

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
import bases  # noqa: E402
from nvd_common import (  # noqa: E402
    DATA_VERSION,
    EXIT_ERROR,
    EXIT_OK,
    PAGE_SIZE,
    positive_int,
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
PASSADAS_INCREMENTAL = 3  # releituras de uma janela incremental que a NVD encurtou
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


class PaginacaoEncurtada(NvdRequestError):
    """A NVD entregou menos registros que o total anunciado."""


def _sleep_for(key):
    return SLEEP_WITH_KEY if key else SLEEP_NO_KEY


def run_pages(conn, base_params, key, store_raw, label, resume_index=0, marcas=None, salvar=None):
    """Pagina uma consulta inteira, gravando checkpoint a cada página.

    O fim é o total que a NVD informa na resposta mais recente, não o da primeira: numa janela
    incremental o total cai quando um CVE é alterado durante a paginação. Página curta antes
    desse total levanta PaginacaoEncurtada — o checkpoint fica gravado e reexecutar retoma.

    `marcas` recebe, por página, [índice antes da página, total informado na resposta]: é o que
    `reler_deslocados` usa para achar onde a lista mudou. `salvar(indice)` persiste a retomada.
    """
    start = resume_index
    anunciado = None
    written = 0
    while True:
        params = dict(base_params)
        params["resultsPerPage"] = PAGE_SIZE
        params["startIndex"] = start
        payload = request_json(params, key)
        total = int(payload.get("totalResults", 0) or 0)
        if anunciado is None:
            anunciado = total
            print("%s: %d CVEs a processar" % (label, total), flush=True)
        if marcas is not None:
            marcas.append([start, total])
        items = payload.get("vulnerabilities") or []
        got = len(items)
        written += store_page(conn, payload, store_raw)
        start += got
        meta_set(conn, "checkpoint_index", start)
        meta_set(conn, "checkpoint_total", total)
        if salvar:
            salvar(start)
        conn.commit()
        pct = (min(start, total) / total * 100) if total else 100.0
        print("  %s  %d/%d (%.1f%%)" % (label, min(start, total), total, pct), flush=True)
        if start >= total:
            break
        if got < PAGE_SIZE:
            raise PaginacaoEncurtada(
                "a NVD devolveu %d registro(s) no índice %d, antes do fim (%d de %d): a paginação "
                "parou no meio; rode o mesmo comando para retomar do checkpoint"
                % (got, start - got, start, total)
            )
        time.sleep(_sleep_for(key))
    return written


def faixas_deslocadas(marcas, total_final):
    """Faixas de índice, na lista atual, onde pode estar um CVE que escorregou para uma página
    já lida.

    Numa janela incremental a lista só perde itens: o CVE alterado durante a paginação ganha
    lastModified depois do fim da janela. Cada saída antes de um item o desloca uma posição para
    trás. Um item escapa da leitura quando cruza a fronteira `c` da próxima página entre duas
    requisições — e a queda do total entre elas limita o quanto ele andou. Depois disso ele ainda
    recua no máximo o que o total caiu até `total_final`. Logo, na lista atual, ele está em
    [c - (total da página anterior - total_final), c).
    """
    faixas = []
    for (_, anterior), (c, atual) in zip(marcas, marcas[1:]):
        if c > 0 and anterior > atual:
            faixas.append([max(0, c - (anterior - total_final)), c])
    faixas.sort()
    juntas = []
    for lo, hi in faixas:
        if juntas and lo <= juntas[-1][1]:
            juntas[-1][1] = max(juntas[-1][1], hi)
        else:
            juntas.append([lo, hi])
    return juntas


def reler_deslocados(conn, base_params, key, store_raw, label, marcas):
    """Relê só as faixas onde a lista mudou, em vez da janela inteira. Saída nova durante a
    releitura alarga as faixas, e a releitura se repete, até PASSADAS_INCREMENTAL vezes."""
    if not marcas:
        return 0
    total_final = marcas[-1][1]
    written = 0
    for _ in range(PASSADAS_INCREMENTAL):
        faixas = faixas_deslocadas(marcas, total_final)
        if not faixas:
            return written
        quantos = sum(hi - lo for lo, hi in faixas)
        print("%s: a lista mudou durante a paginação; relendo %d posição(ões) em %d faixa(s)"
              % (label, quantos, len(faixas)), flush=True)
        menor = total_final
        for lo, hi in faixas:
            pos = lo
            while pos < hi:
                tamanho = min(PAGE_SIZE, hi - pos)
                params = dict(base_params, resultsPerPage=tamanho, startIndex=pos)
                payload = request_json(params, key)
                written += store_page(conn, payload, store_raw)
                menor = min(menor, int(payload.get("totalResults", menor) or 0))
                pos += tamanho
                time.sleep(_sleep_for(key))
        conn.commit()
        if menor >= total_final:
            return written
        total_final = menor  # mais saídas durante a releitura: as faixas crescem
    print("aviso: %s mudou de novo durante a releitura; os CVEs que saíram dela foram alterados "
          "depois do fim da janela e entram no próximo --update" % label, flush=True)
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


INC_KEYS = ("inc_fim", "inc_inicio", "inc_indice", "inc_marcas")


def incremental(conn, key, store_raw):
    """Sincroniza o que mudou desde o last_sync, em janelas de até MAX_WINDOW_DAYS.

    A NVD pagina sobre dados vivos: CVE alterado durante a paginação sai da janela (o
    lastModified novo passa do fim dela) e entra no próximo --update, mas a saída desloca os
    índices e pode fazer um CVE inalterado escorregar para uma página já lida. Esses são
    recuperados por `reler_deslocados`, que relê só as faixas onde o total caiu.

    Interrompido (rede, Ctrl+C, computador em suspensão), o estado fica em meta.inc_*: a próxima
    execução retoma a mesma janela e o mesmo índice, com o mesmo fim, e a queda do total durante
    a pausa entra nas marcas como qualquer outra.
    """
    last = meta_get(conn, "last_sync")
    if not last:
        raise NvdRequestError("base sem last_sync: rode o download completo antes do --update")
    if meta_get(conn, "inc_fim"):
        end = parse_stamp(meta_get(conn, "inc_fim"))
        start = parse_stamp(meta_get(conn, "inc_inicio"))
        indice = int(meta_get(conn, "inc_indice", "0") or 0)
        marcas = json.loads(meta_get(conn, "inc_marcas", "[]") or "[]")
        print("retomando a atualização interrompida: janela a partir de %s, índice %d"
              % (stamp(start), indice), flush=True)
    else:
        start, end, indice, marcas = parse_stamp(last), now_utc(), 0, []
        meta_set(conn, "inc_fim", stamp(end))
        meta_set(conn, "inc_inicio", stamp(start))
        meta_set(conn, "inc_indice", 0)
        meta_set(conn, "inc_marcas", "[]")
        conn.commit()
    written = 0
    window = 0
    while start < end:
        chunk_end = min(start + timedelta(days=MAX_WINDOW_DAYS), end)
        window += 1
        label = "janela %d" % window
        params = {"lastModStartDate": stamp(start), "lastModEndDate": stamp(chunk_end)}

        def salvar(pos, marcas=marcas):
            meta_set(conn, "inc_indice", pos)
            meta_set(conn, "inc_marcas", json.dumps(marcas))

        written += run_pages(conn, params, key, store_raw, label, resume_index=indice,
                             marcas=marcas, salvar=salvar)
        written += reler_deslocados(conn, params, key, store_raw, label, marcas)
        start, indice, marcas = chunk_end, 0, []
        meta_set(conn, "inc_inicio", stamp(start))
        meta_set(conn, "inc_indice", 0)
        meta_set(conn, "inc_marcas", "[]")
        conn.commit()
    meta_set(conn, "last_sync", stamp(end))
    for chave in INC_KEYS:
        meta_set(conn, chave, "")
    # O checkpoint_index de run_pages é do download completo; zerar evita "download pendente"
    # fantasma no --stats.
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
    parser.add_argument("--db", help="caminho do arquivo SQLite (padrão: ~/.nist-aegis/bases/nvd.sqlite, "
                        "ou ~/.nvd/nvd.sqlite de versões anteriores, quando existir)")
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument("--update", action="store_true", help="sincronização incremental")
    modo.add_argument("--reindex", action="store_true",
                      help="reprocessa o JSON bruto já gravado, sem rede")
    parser.add_argument(
        "--skip-raw",
        action="store_true",
        help="não guarda o JSON bruto de cada CVE (base bem menor, mas sem --reindex futuro)",
    )
    parser.add_argument(
        "--pagina", type=positive_int(2000), default=2000, metavar="N",
        help="CVEs por requisição (padrão e máximo 2000). Com a NVD instável, páginas menores, como "
             "500, dão menos timeout: a de 2000 chega a 16 MB",
    )
    return parser


def main(argv=None):
    global PAGE_SIZE
    configure_stdio()
    args = build_parser().parse_args(argv)
    PAGE_SIZE = args.pagina
    args.db = bases.resolve_nvd(args.db)
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
