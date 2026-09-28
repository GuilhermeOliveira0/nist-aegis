---
name: cve
description: Consulta de CVEs na base da NVD, local ou pela API pública. Mantém um espelho SQLite em ~/.nvd/nvd.sqlite com retomada por checkpoint, e consulta por identificador de CVE, por termo ou por vendor:product de CPE, com filtro de severidade mínima. Use quando precisar verificar se uma dependência tem CVE conhecido, consultar um CVE específico, ou checar o estado e a data de sincronização da base local de vulnerabilidades.
allowed-tools: Read, Glob, Grep
---

# Consulta de CVEs da NVD

Três scripts em `scripts/`, todos em Python 3 e sem dependência externa — só a
biblioteca padrão.

A chave de API vem da variável de ambiente `NVD_API_KEY` e **nunca** é impressa nem
gravada em arquivo. Sem chave a API aplica 5 requisições por 30 segundos em vez de 50, o
que faz o download completo passar de 2-3 minutos para 15-20.

## Base local

Download completo para `~/.nvd/nvd.sqlite`:

```bash
python scripts/download_db.py --db ~/.nvd/nvd.sqlite
```

Sincronização incremental, a partir do último sync registrado:

```bash
python scripts/download_db.py --db ~/.nvd/nvd.sqlite --update
```

O download é paginado de 2000 em 2000 e grava `meta.checkpoint_index` a cada página. Se
o comando for cortado por timeout ou a rede cair, **rode o mesmo comando de novo**: ele
retoma do checkpoint. `--skip-raw` descarta o JSON bruto de cada CVE e reduz muito o
tamanho do arquivo, sem perda para as consultas.

## Consulta local

```bash
python scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --stats
python scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --cve CVE-2021-44228
python scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --keyword lodash --min-severity HIGH --limit 3
python scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --product microsoft:windows --min-severity CRITICAL --limit 3
```

- `--stats` devolve total de CVEs, tamanho, data do último sync, se a base está marcada
  como completa, se há checkpoint pendente, e a contagem por severidade. Sync com mais de
  7 dias é sinalizado como desatualizado.
- `--keyword` busca na descrição e no `vendor:product` dos CPEs.
- `--product` casa por prefixo de `vendor:product`, então `microsoft:windows` alcança
  `windows_10` e `windows_server_2019`.
- `--min-severity` aceita `LOW`, `MEDIUM`, `HIGH` e `CRITICAL`.
- `--json` troca a saída legível por JSON, para consumo por outra ferramenta.

Saída: código 0 com resultados, 1 sem resultados.

## Consulta direta na API

Quando não há base local, ou para conferir um CVE recém-publicado:

```bash
python scripts/nvd_lookup.py --cve CVE-2021-44228
python scripts/nvd_lookup.py --keyword lodash --min-severity HIGH --limit 3
```

## Esquema da base

| Tabela | Conteúdo |
| :--- | :--- |
| `cves` | Um registro por CVE: identificador, datas, descrição, CVSS (versão, score, severidade, vetor), CWEs e o JSON bruto |
| `cpes` | Um registro por CPE afetado: `criteria`, `vendor:product` normalizado e os limites de versão |
| `meta` | `last_sync`, `complete`, `checkpoint_index`, `checkpoint_total`, `schema_version` |

A prioridade de métrica é CVSS 3.1, depois 3.0, depois 2.0 — a primeira encontrada é a
gravada, e a versão fica registrada em `cvss_version`.

## Regras

- A chave de API vem do ambiente. Nunca a escreva em arquivo, script, log ou saída de
  terminal.
- Os scripts só leem da rede e escrevem no arquivo SQLite indicado em `--db`. Nenhum
  deles altera código do projeto.
- `local_lookup.py` não faz rede e não lê `NVD_API_KEY`.
