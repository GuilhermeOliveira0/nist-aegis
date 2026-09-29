#!/usr/bin/env python3
"""Baixa e atualiza o espelho local do OSV (~/.nist-aegis/bases/osv.sqlite).

Uso:
    python download_osv.py                      baixa os ecossistemas que ainda não estão na base
    python download_osv.py --update             atualiza só o que mudou desde a última vez
    python download_osv.py --completo           baixa tudo de novo
    python download_osv.py --stats              estado da base, sem rede
    python download_osv.py --ecossistemas npm,PyPI

Privacidade: o download é do arquivo inteiro de cada ecossistema (ou, no --update, da lista
pública de registros alterados e desses registros), igual para qualquer pessoa. Nada do projeto
auditado sai da máquina — nem nome de pacote. Depois disso a consulta (sca_scan.py --osv-local)
roda sem rede.

Integridade: cada arquivo é conferido pelo MD5 que o Google Cloud Storage publica no cabeçalho
x-goog-hash; divergência descarta o arquivo. A importação de um ecossistema é uma transação: se
falhar no meio, a base fica como estava. O .zip baixado é apagado depois de importado.

Só biblioteca padrão. Códigos de saída: 0 ok, 2 argumento inválido, 3 erro.
"""

import argparse
import base64
import email.utils
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bases  # noqa: E402
import osv_local  # noqa: E402

BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
USER_AGENT = "nist-aegis/1.2"
CHUNK = 1024 * 1024
# Acima disso, baixar o arquivo inteiro é mais barato que buscar registro por registro.
LIMITE_INCREMENTAL = 2000
# O corte recua uma margem: registro reprocessado não faz mal, registro perdido faz.
MARGEM_COMPLETO = timedelta(hours=6)
MARGEM_INCREMENTAL = timedelta(hours=1)
ID_VALIDO = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

EXIT_OK, EXIT_USAGE, EXIT_ERROR = 0, 2, 3


class DownloadErro(RuntimeError):
    pass


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(texto):
    return datetime.strptime(texto[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- rede

def _abrir(url, timeout=120, tentativas=4):
    espera = 2.0
    for tentativa in range(1, tentativas + 1):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}),
                                          timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and tentativa < tentativas:
                time.sleep(espera)
                espera *= 2
                continue
            raise DownloadErro("HTTP %d em %s" % (exc.code, url))
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if tentativa < tentativas:
                time.sleep(espera)
                espera *= 2
                continue
            raise DownloadErro("falha de rede em %s: %s" % (url, type(exc).__name__))
    raise DownloadErro("falhou após %d tentativas: %s" % (tentativas, url))


def _md5_publicado(headers):
    for valor in headers.get_all("x-goog-hash") or []:
        for parte in valor.split(","):
            nome, _, dado = parte.strip().partition("=")
            if nome == "md5":
                return dado
    return None


def baixar_arquivo(url, destino, progresso=None):
    """Grava em destino.part, confere o MD5 e renomeia. Devolve o Last-Modified (datetime)."""
    parcial = destino + ".part"
    resp = _abrir(url)
    try:
        esperado = _md5_publicado(resp.headers)
        tamanho = int(resp.headers.get("Content-Length") or 0)
        ultima = resp.headers.get("Last-Modified")
        md5 = hashlib.md5()
        lido = 0
        with open(parcial, "wb") as fh:
            while True:
                bloco = resp.read(CHUNK)
                if not bloco:
                    break
                fh.write(bloco)
                md5.update(bloco)
                lido += len(bloco)
                if progresso:
                    progresso(lido, tamanho)
    except (OSError, urllib.error.URLError) as exc:
        _apagar(parcial)
        raise DownloadErro("download interrompido: %s" % type(exc).__name__)
    finally:
        resp.close()
    if tamanho and lido != tamanho:
        _apagar(parcial)
        raise DownloadErro("download incompleto: %d de %d bytes" % (lido, tamanho))
    if esperado is None:
        _apagar(parcial)
        raise DownloadErro("o servidor não publicou o MD5 do arquivo; sem ele a integridade não é conferida")
    if base64.b64encode(md5.digest()).decode() != esperado:
        _apagar(parcial)
        raise DownloadErro("MD5 não confere: o arquivo foi descartado")
    os.replace(parcial, destino)
    try:
        return email.utils.parsedate_to_datetime(ultima).astimezone(timezone.utc) if ultima else None
    except (TypeError, ValueError):
        return None


def baixar_texto(url, limite=64 * 1024 * 1024):
    resp = _abrir(url)
    try:
        dados = resp.read(limite + 1)
    finally:
        resp.close()
    if len(dados) > limite:
        raise DownloadErro("resposta maior que o esperado em %s" % url)
    return dados.decode("utf-8", errors="replace")


def _apagar(caminho):
    try:
        os.remove(caminho)
    except OSError:
        pass


# ---------------------------------------------------------------- sincronização

def sync_completo(conn, eco, downloads, saida=print):
    os.makedirs(downloads, exist_ok=True)
    destino = os.path.join(downloads, "%s.zip" % eco)
    url = "%s/%s/all.zip" % (BASE_URL, urllib.parse.quote(eco))
    marcos = set()

    def progresso(lido, total):
        if total:
            pct = int(lido * 100 / total) // 25 * 25
            if pct not in marcos:
                marcos.add(pct)
                saida("  %s: %d%% de %.0f MB" % (eco, pct, total / 1e6))

    saida("%s: baixando o arquivo completo" % eco)
    ultima = baixar_arquivo(url, destino, progresso)
    try:
        saida("%s: importando" % eco)
        total = osv_local.importar_zip(conn, eco, destino)
    finally:
        _apagar(destino)
    corte = (ultima or datetime.now(timezone.utc)) - MARGEM_COMPLETO
    osv_local.meta_set(conn, "eco:%s:atualizado_em" % eco, iso(datetime.now(timezone.utc)))
    osv_local.meta_set(conn, "eco:%s:corte" % eco, iso(corte))
    osv_local.meta_set(conn, "eco:%s:registros" % eco, total)
    saida("%s: %d registros importados" % (eco, total))
    return total


def ids_alterados(csv_texto, corte):
    """modified_id.csv vem do mais novo para o mais antigo: lê até passar do corte."""
    ids, mais_novo = [], None
    for linha in csv_texto.splitlines():
        data, _, vid = linha.strip().partition(",")
        if not vid:
            continue
        try:
            quando = parse_iso(data)
        except ValueError:
            continue
        if mais_novo is None:
            mais_novo = quando
        if quando <= corte:
            break
        if ID_VALIDO.match(vid):
            ids.append(vid)
    return ids, mais_novo


def sync_incremental(conn, eco, downloads, saida=print):
    corte_txt = osv_local.meta_get(conn, "eco:%s:corte" % eco)
    if not corte_txt:
        return sync_completo(conn, eco, downloads, saida)
    corte = parse_iso(corte_txt)
    csv_texto = baixar_texto("%s/%s/modified_id.csv" % (BASE_URL, urllib.parse.quote(eco)))
    ids, mais_novo = ids_alterados(csv_texto, corte)
    if len(ids) > LIMITE_INCREMENTAL:
        saida("%s: %d registros alterados; mais rápido baixar o arquivo completo" % (eco, len(ids)))
        return sync_completo(conn, eco, downloads, saida)
    saida("%s: %d registro(s) alterado(s) desde %s" % (eco, len(ids), corte_txt))
    falhas = []
    conn.execute("BEGIN")
    try:
        for vid in ids:
            try:
                texto = baixar_texto("%s/%s/%s.json" % (BASE_URL, urllib.parse.quote(eco), urllib.parse.quote(vid)),
                                     limite=osv_local.MAX_REGISTRO_BYTES)
                osv_local.importar_registro(conn, json.loads(texto), eco)
            except (DownloadErro, ValueError) as exc:
                falhas.append("%s: %s" % (vid, exc))
        osv_local.limpar_orfaos(conn)
        agora = datetime.now(timezone.utc)
        osv_local.meta_set(conn, "eco:%s:atualizado_em" % eco, iso(agora))
        # com falha, o corte não anda: o próximo --update tenta de novo os mesmos registros
        if not falhas and mais_novo is not None:
            osv_local.meta_set(conn, "eco:%s:corte" % eco, iso(mais_novo - MARGEM_INCREMENTAL))
        total = conn.execute("SELECT COUNT(DISTINCT vuln_id) FROM affected WHERE ecosystem = ?", (eco,)).fetchone()[0]
        osv_local.meta_set(conn, "eco:%s:registros" % eco, total)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    if falhas:
        saida("%s: %d registro(s) não baixado(s); o próximo --update tenta de novo" % (eco, len(falhas)))
    return len(ids) - len(falhas)


# ---------------------------------------------------------------- estado

def estado(db):
    if not os.path.exists(db):
        return {"caminho": db, "estado": "ausente", "ecossistemas": {}}
    base = osv_local.BaseOsvLocal(db)
    try:
        info = base.estado()
        info["vulnerabilidades"] = base.conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    finally:
        base.close()
    info["tamanho_mb"] = round(os.path.getsize(db) / 1e6, 1)
    return info


def imprimir_estado(info):
    print("base OSV local: %s" % info["caminho"])
    if info["estado"] == "ausente":
        print("estado: AUSENTE — rode download_osv.py para criar")
        return
    print("tamanho: %s MB; vulnerabilidades: %s" % (info.get("tamanho_mb"), info.get("vulnerabilidades")))
    for eco in osv_local.ECOSSISTEMAS:
        dados = info["ecossistemas"].get(eco)
        if not dados:
            print("  %-10s não baixado" % eco)
            continue
        alerta = " (DESATUALIZADO: rode --update)" if (dados["idade_dias"] or 0) > 7 else ""
        print("  %-10s %6d registros, atualizado em %s (%.1f dia(s))%s" % (
            eco, dados["registros"], dados["atualizado_em"], dados["idade_dias"] or 0, alerta))


# ---------------------------------------------------------------- linha de comando

def build_parser():
    parser = argparse.ArgumentParser(description="Espelho local do OSV.")
    parser.add_argument("--db", help="arquivo SQLite (padrão: %s)" % bases.osv_default())
    parser.add_argument("--ecossistemas", help="lista separada por vírgula (padrão: %s)" % ",".join(osv_local.ECOSSISTEMAS))
    grupo = parser.add_mutually_exclusive_group()
    grupo.add_argument("--update", action="store_true", help="atualiza só o que mudou")
    grupo.add_argument("--completo", action="store_true", help="baixa tudo de novo")
    grupo.add_argument("--stats", action="store_true", help="mostra o estado da base, sem rede")
    return parser


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    parser = build_parser()
    args = parser.parse_args(argv)
    db = bases.resolve_osv(args.db)
    ecos = list(osv_local.ECOSSISTEMAS)
    if args.ecossistemas:
        ecos = [e.strip() for e in args.ecossistemas.split(",") if e.strip()]
        invalidos = [e for e in ecos if e not in osv_local.ECOSSISTEMAS]
        if invalidos:
            parser.error("ecossistema desconhecido: %s (use %s)" % (", ".join(invalidos), ", ".join(osv_local.ECOSSISTEMAS)))
    if args.stats:
        imprimir_estado(estado(db))
        return EXIT_OK

    conn = osv_local.connect(db, create=True)
    osv_local.init_schema(conn)
    erros = []
    try:
        for eco in ecos:
            ja_tem = osv_local.meta_get(conn, "eco:%s:corte" % eco)
            try:
                if args.completo or not ja_tem:
                    sync_completo(conn, eco, bases.downloads_dir())
                elif args.update:
                    sync_incremental(conn, eco, bases.downloads_dir())
                else:
                    print("%s: já na base (use --update para atualizar)" % eco)
            except (DownloadErro, osv_local.BaseOsvErro) as exc:
                erros.append("%s: %s" % (eco, exc))
                print("ERRO: %s: %s" % (eco, exc), file=sys.stderr)
    finally:
        conn.close()
    imprimir_estado(estado(db))
    return EXIT_ERROR if erros else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
