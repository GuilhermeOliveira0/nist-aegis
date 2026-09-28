#!/usr/bin/env python3
"""Consulta CVEs direto na API pública 2.0 da NVD, sem base local.

Uso:
    python nvd_lookup.py --cve CVE-2021-44228
    python nvd_lookup.py --keyword lodash --min-severity HIGH --limit 3
    python nvd_lookup.py --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" --limit 5

A chave é lida de NVD_API_KEY e nunca é impressa. Sem chave, a API aplica o
limite de 5 requisições por 30 s.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nvd_common import (  # noqa: E402
    SEVERITY_RANK,
    api_key,
    extract_cwes,
    extract_description,
    extract_metrics,
    min_rank,
    request_json,
)


def flatten(cve):
    version, score, severity, vector = extract_metrics(cve)
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": extract_description(cve),
        "cvss_version": version,
        "base_score": score,
        "base_severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 0),
        "vector_string": vector,
        "cwes": extract_cwes(cve),
    }


def render(item, width=100):
    score = "n/d" if item["base_score"] is None else "%.1f" % item["base_score"]
    lines = [
        "%s  %s  %s (CVSS %s)"
        % (item["cve_id"], score, item["base_severity"] or "n/d", item["cvss_version"] or "n/d")
    ]
    desc = (item["description"] or "").replace("\n", " ").strip()
    if len(desc) > width:
        desc = desc[: width - 1] + "…"
    lines.append("  " + desc)
    if item["cwes"]:
        lines.append("  CWE: %s" % item["cwes"])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Consulta CVEs na API pública da NVD.")
    parser.add_argument("--cve", help="consulta um CVE por identificador")
    parser.add_argument("--keyword", help="busca por termo")
    parser.add_argument("--cpe", help="busca por CPE 2.3 completo")
    parser.add_argument(
        "--min-severity",
        choices=sorted(SEVERITY_RANK, key=SEVERITY_RANK.get),
        help="severidade mínima, aplicada ao resultado",
    )
    parser.add_argument("--limit", type=int, default=20, help="máximo de resultados")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    args = parser.parse_args()

    if not (args.cve or args.keyword or args.cpe):
        sys.exit("ERRO: informe --cve, --keyword ou --cpe.")

    key = api_key()
    if not args.json:
        sys.stderr.write(
            "chave NVD_API_KEY: %s\n" % ("presente" if key else "ausente (modo limitado)")
        )

    params = {"resultsPerPage": min(max(args.limit, 1), 2000)}
    if args.cve:
        params["cveId"] = args.cve
    if args.keyword:
        params["keywordSearch"] = args.keyword
    if args.cpe:
        params["cpeName"] = args.cpe

    payload = request_json(params, key)
    if payload is None:
        print("nenhum CVE encontrado para os critérios informados")
        return 1

    items = [flatten(entry.get("cve") or {}) for entry in payload.get("vulnerabilities") or []]
    rank = min_rank(args.min_severity)
    if rank:
        items = [item for item in items if item["severity_rank"] >= rank]
    items.sort(key=lambda item: (-(item["base_score"] or 0), item["cve_id"] or ""))
    items = items[: args.limit]

    if args.json:
        print(json.dumps(items, ensure_ascii=False, indent=2))
        return 0 if items else 1

    if not items:
        print("nenhum CVE encontrado para os critérios informados")
        return 1
    for item in items:
        print(render(item))
        print()
    print("%d resultado(s) de %d totais na consulta" % (len(items), payload.get("totalResults", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
