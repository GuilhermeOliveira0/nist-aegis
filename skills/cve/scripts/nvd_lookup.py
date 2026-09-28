#!/usr/bin/env python3
"""Consulta CVEs direto na API pública 2.0 da NVD, sem base local.

Uso:
    python nvd_lookup.py --cve CVE-2021-44228
    python nvd_lookup.py --keyword lodash --min-severity HIGH --limit 3
    python nvd_lookup.py --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" --limit 5

A API devolve do CVE mais antigo para o mais novo. Por isso o script busca todas as páginas
(até --max-paginas) e só depois filtra por severidade e ordena por nota: filtrar a primeira
página devolveria só CVEs antigos. `--cpe` com a versão exata é a consulta mais precisa, porque
a NVD aplica as faixas de versão no servidor — mas só alcança CVEs que a NVD analisou.

A chave é lida de NVD_API_KEY e nunca é impressa. Sem chave, a API aplica o limite de 5
requisições por 30 s.

Códigos de saída: 0 com resultado, 1 sem resultado, 2 argumento inválido, 3 erro de execução.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nvd_common import (  # noqa: E402
    EXIT_ERROR,
    EXIT_NONE,
    EXIT_OK,
    PAGE_SIZE,
    SEVERITY_CHOICES,
    SLEEP_NO_KEY,
    SLEEP_WITH_KEY,
    NvdRequestError,
    api_key,
    configure_stdio,
    extract_cwes,
    extract_description,
    extract_kev,
    extract_metrics,
    format_cve,
    min_rank,
    positive_int,
    request_json,
    silence_broken_pipe,
)


def flatten(cve):
    metric = extract_metrics(cve)
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": extract_description(cve),
        "cvss_version": metric["version"],
        "base_score": metric["score"],
        "base_severity": metric["severity"],
        "severity_rank": metric["rank"],
        "vector_string": metric["vector"],
        "cvss_source": metric["source"],
        "cvss_type": metric["type"],
        "cwes": extract_cwes(cve),
        "kev_added": extract_kev(cve),
    }


def fetch_all(params, key, max_pages):
    """Devolve (registros, total informado pela API, se parou em --max-paginas)."""
    sleep_for = SLEEP_WITH_KEY if key else SLEEP_NO_KEY
    cves = []
    start = 0
    total = None
    pages = 0
    while True:
        page_params = dict(params)
        page_params["resultsPerPage"] = PAGE_SIZE
        page_params["startIndex"] = start
        payload = request_json(page_params, key)
        if total is None:
            total = int(payload.get("totalResults", 0) or 0)
        batch = payload.get("vulnerabilities") or []
        cves.extend(entry.get("cve") or {} for entry in batch)
        start += len(batch)
        pages += 1
        if start >= total or not batch:
            return cves, total, False
        if pages >= max_pages:
            return cves, total, True
        time.sleep(sleep_for)


def build_parser():
    parser = argparse.ArgumentParser(description="Consulta CVEs na API pública da NVD.")
    parser.add_argument("--cve", help="consulta um CVE por identificador")
    parser.add_argument("--keyword", help="busca por termo na descrição (a NVD casa por prefixo de palavra)")
    parser.add_argument("--cpe", help="busca por CPE 2.3 completo, com versão exata")
    parser.add_argument("--min-severity", choices=SEVERITY_CHOICES,
                        help="severidade mínima, aplicada depois de buscar todas as páginas")
    parser.add_argument("--limit", type=positive_int(100000), default=20, help="máximo de resultados")
    parser.add_argument("--max-paginas", type=positive_int(100), default=5,
                        help="teto de páginas de 2000 CVEs (padrão 5)")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    parser.add_argument("--incluir-rejeitados", action="store_true", help="inclui CVEs com status Rejected")
    parser.add_argument("--excluir-sem-nota", action="store_true",
                        help="com --min-severity, descarta CVE sem nota (por padrão ele aparece marcado)")
    return parser


def main(argv=None):
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.cve or args.keyword or args.cpe):
        parser.error("informe --cve, --keyword ou --cpe")

    key = api_key()
    if not args.json:
        sys.stderr.write("chave NVD_API_KEY: %s\n" % ("presente" if key else "ausente (modo limitado)"))

    params = {}
    if args.cve:
        params["cveId"] = args.cve.strip()
    if args.keyword:
        params["keywordSearch"] = args.keyword.strip()
    if args.cpe:
        params["cpeName"] = args.cpe.strip()

    try:
        cves, total, truncated = fetch_all(params, key, args.max_paginas)
    except NvdRequestError as exc:
        print("ERRO: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    items = [flatten(cve) for cve in cves if cve]
    if not args.incluir_rejeitados:
        items = [item for item in items if (item["vuln_status"] or "") != "Rejected"]
    rank = min_rank(args.min_severity)
    if rank:
        items = [
            item for item in items
            if item["severity_rank"] >= rank or (item["severity_rank"] == 0 and not args.excluir_sem_nota)
        ]
    items.sort(key=lambda item: (-item["severity_rank"], -(item["base_score"] or 0), item["cve_id"] or ""))
    shown = items[: args.limit]

    try:
        if args.json:
            print(json.dumps({
                "total_api": total,
                "paginas_truncadas": truncated,
                "total_filtrado": len(items),
                "mostrando": len(shown),
                "resultados": shown,
            }, ensure_ascii=False, indent=2))
            return EXIT_OK if shown else EXIT_NONE
        if not shown:
            print("nenhum CVE encontrado para os critérios informados")
        for item in shown:
            print(format_cve(item))
            print()
        if shown:
            print("mostrando %d de %d resultado(s) filtrado(s); a API informou %d no total"
                  % (len(shown), len(items), total))
        if truncated:
            print("aviso: a busca parou em %d página(s) de %d CVEs; aumente --max-paginas para "
                  "cobrir tudo" % (args.max_paginas, PAGE_SIZE))
    except BrokenPipeError:
        silence_broken_pipe()
        return EXIT_OK
    return EXIT_OK if shown else EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
