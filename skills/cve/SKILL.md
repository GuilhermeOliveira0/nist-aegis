---
name: cve
description: Vulnerabilidades conhecidas em dependências e consulta de CVEs. Varre os lockfiles de um projeto e casa pacote e versão exata no OSV — pela base local, sem rede, ou pela API —, com nota, CWE e KEV da NVD (sca_scan.py); mantém espelhos SQLite do OSV e da NVD em ~/.nist-aegis/bases/; e consulta por identificador de CVE, por termo ou por vendor:product de CPE, com filtro de severidade mínima. Use quando precisar saber se as dependências de um projeto têm vulnerabilidade conhecida, consultar um CVE específico, ou checar o estado e a data de sincronização das bases locais.
allowed-tools:
  - Read
  - Glob
  - Grep
  - Bash(python "${CLAUDE_SKILL_DIR}/scripts/sca_scan.py" *)
  - Bash(python "${CLAUDE_SKILL_DIR}/scripts/local_lookup.py" *)
  - Bash(python "${CLAUDE_SKILL_DIR}/scripts/nvd_lookup.py" *)
---

# Vulnerabilidades em dependências e consulta de CVEs

Scripts em `${CLAUDE_SKILL_DIR}/scripts/`, todos em Python 3 e sem dependência externa — só a
biblioteca padrão (`sca_scan.py` pede Python 3.11 ou superior).

## Onde ficam as bases

```
~/.nist-aegis/
├── bases/
│   ├── nvd.sqlite     espelho da NVD (download_db.py)
│   └── osv.sqlite     espelho do OSV (download_osv.py)
└── downloads/         arquivos do OSV em trânsito, apagados depois da importação
```

`NIST_AEGIS_HOME` troca a pasta. Uma NVD de versão anterior em `~/.nvd/nvd.sqlite` continua sendo
encontrada enquanto não houver uma em `bases/`. Sem `--db`, todos os scripts usam esses caminhos.

## Dependências de um projeto

```bash
python "${CLAUDE_SKILL_DIR}/scripts/sca_scan.py" --raiz "<projeto>" --saida "<projeto>/security-audit/.trabalho/sca.json" --osv-local
```

Com `--osv-local`, a consulta é feita na base OSV local e **nada sai da máquina**. Sem essa
opção, a consulta vai para a API (api.osv.dev); com `--offline` e sem `--osv-local`, não há
consulta, só o inventário. Prefira `--osv-local`; use a API só quando o usuário pedir.

Lê `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 e Berry), `pnpm-lock.yaml`
(leitura simplificada), `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `go.mod`,
`Cargo.lock`, `composer.lock`, `Gemfile.lock`, `packages.lock.json` e `gradle.lockfile`, e
consulta o **OSV** por nome e versão exata. Grava um JSON com o inventário, os pacotes
vulneráveis (IDs, CVEs, nota, CWE, KEV, versões corrigidas, cadeia até o pacote direto), os
pacotes maliciosos conhecidos (`MAL-*`), os manifestos sem lockfile, as faixas sem pin e as
fontes fora do registro público.

**Base local:** o JSON traz `consulta.modo` (`local`, `online` ou `desligada`), `base_osv` com a
data de cada ecossistema e `consulta.nao_avaliados` — pacote de ecossistema que não está na base,
ou versão num formato que o comparador não reconhece. Não avaliado nunca quer dizer "sem
vulnerabilidade". Base com mais de 7 dias gera aviso em `limites`.

**Privacidade no modo API:** só nome, ecossistema e versão de cada pacote público vão para
api.osv.dev. Não é enviado, em nenhum ecossistema, o que o projeto declara com fonte privada (git, URL, caminho
local, índice ou registro próprio, escopo npm do `.npmrc` ou do `.yarnrc.yml`), módulo Go coberto
por `GOPRIVATE`/`GONOPROXY`/`GONOSUMDB`, membro de workspace nem versão que seja URL ou caminho;
`--nao-enviar <regex>` exclui outros nomes; `--offline` não faz rede nenhuma e produz só o
inventário. Usuário, senha e token de URL de origem são removidos antes de gravar o JSON. Mostre
isso ao usuário antes de rodar.

**Rode os scripts sempre pelo caminho completo, entre aspas, exatamente como nos exemplos.**
Nunca use `scripts/...` relativo: ele aponta para a pasta `scripts/` do projeto aberto, que é
código de terceiro, não deste plugin.

A chave de API vem da variável de ambiente `NVD_API_KEY` e **nunca** é impressa nem gravada em
arquivo. Sem chave a API aplica 5 requisições por 30 segundos em vez de 50.

## Bases locais

**O download e a atualização das bases são decisão do usuário.** Não os rode por conta própria:
mostre o comando e deixe o usuário executar. Por isso `download_osv.py` e `download_db.py` não
estão nas ferramentas liberadas desta skill.

### OSV

Baixa o arquivo completo de cada ecossistema (npm, PyPI, Go, Maven, crates.io, Packagist,
RubyGems, NuGet; cerca de 300 MB compactados, a maior parte do npm), confere o MD5 publicado
pelo Google Cloud Storage, importa e apaga o arquivo baixado:

```bash
python "${CLAUDE_SKILL_DIR}/scripts/download_osv.py"
```

Atualização: baixa a lista pública de registros alterados e só esses registros; com mais de
2000 alterados num ecossistema, baixa o arquivo dele de novo:

```bash
python "${CLAUDE_SKILL_DIR}/scripts/download_osv.py" --update
```

`--stats` mostra o estado sem rede; `--ecossistemas npm,PyPI` limita; `--completo` baixa tudo
de novo. O download é o mesmo para qualquer pessoa: nada do projeto sai da máquina. Interrompido,
rode o mesmo comando: o ecossistema já importado é pulado, e um ecossistema que falhou no meio fica
como estava.

### NVD

Download completo (cerca de 3 GB; pode passar de uma hora):

```bash
python "${CLAUDE_SKILL_DIR}/scripts/download_db.py"
```

Sincronização incremental, a partir do último sync registrado:

```bash
python "${CLAUDE_SKILL_DIR}/scripts/download_db.py" --update
```

O download é paginado de 2000 em 2000 e grava `meta.checkpoint_index` a cada página. Se o
comando for cortado por timeout, a rede cair ou a API devolver erro, **rode o mesmo comando de
novo**: ele retoma do checkpoint. A base só é marcada como completa quando a paginação chega ao
total informado pela NVD. `--skip-raw` descarta o JSON bruto de cada CVE e reduz muito o tamanho
do arquivo, mas impede o `--reindex` futuro.

Base criada por uma versão anterior destes scripts (o `--stats` mostra "dados: versão 1")
ganha CVSS 4.0, KEV e as faixas de versão completas com um reprocessamento local, sem rede:

```bash
python "${CLAUDE_SKILL_DIR}/scripts/download_db.py" --reindex
```

## Consulta local

```bash
python "${CLAUDE_SKILL_DIR}/scripts/local_lookup.py" --stats
python "${CLAUDE_SKILL_DIR}/scripts/local_lookup.py" --cve CVE-2021-44228
python "${CLAUDE_SKILL_DIR}/scripts/local_lookup.py" --keyword 'lodash' --min-severity HIGH --limit 3
python "${CLAUDE_SKILL_DIR}/scripts/local_lookup.py" --product 'microsoft:windows' --min-severity CRITICAL --limit 3
```

- `--stats` devolve total de CVEs, rejeitados, válidos sem nota, tamanho, data do último sync,
  a linha `estado do sync` (sempre presente: `recente`, `DESATUALIZADO`, `INCOMPLETA`,
  `NUNCA SINCRONIZADA` ou `VAZIA`), a contagem por severidade e se a base precisa de
  `--reindex`.
- `--keyword` casa o termo como **palavra inteira** na descrição (`ws` não casa "allows") ou
  como vendor/produto exato de CPE. Separadores `-`, `_`, `.` e espaço se equivalem, então
  `python_jose` casa `python-jose`.
- `--product` casa por prefixo de `vendor:product`, então `microsoft:windows` alcança
  `windows_10` e `windows_server_2019`. CPE de plataforma (`vulnerable: false`) não conta; use
  `--incluir-plataforma` para contar.
- `--min-severity` aceita `LOW`, `MEDIUM`, `HIGH` e `CRITICAL` e usa a maior nota entre a NVD
  e a CNA. **CVE sem nota nunca é filtrado**: aparece marcado `SEM NOTA`, salvo com
  `--excluir-sem-nota`. CVE `Rejected` fica fora, salvo com `--incluir-rejeitados`.
- `--detalhes` mostra a descrição inteira e as faixas de versão de cada CPE.
- `--json` troca a saída por um objeto `{total, mostrando, resultados}`, com os CPEs de cada CVE.
- Quando há mais resultados que `--limit`, a saída diz `mostrando N de M`.

Termo de busca vai sempre entre aspas simples, e só se casar
`^[A-Za-z0-9@_][A-Za-z0-9@._/:+-]{0,213}$`. Termo curto e comum continua ambíguo mesmo como
palavra inteira: para dependência, prefira `--product vendor:product`.

Códigos de saída de todos os scripts: **0** com resultado, **1** sem resultado, **2** argumento
inválido, **3** erro de execução (base ausente, rede, API). Código 2 ou 3 é falha da consulta,
nunca "sem CVE".

## Consulta direta na API

Quando não há base local, ou para conferir um CVE recém-publicado:

```bash
python "${CLAUDE_SKILL_DIR}/scripts/nvd_lookup.py" --cve CVE-2021-44228
python "${CLAUDE_SKILL_DIR}/scripts/nvd_lookup.py" --keyword 'lodash' --min-severity HIGH --limit 3
python "${CLAUDE_SKILL_DIR}/scripts/nvd_lookup.py" --cpe 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'
```

A API devolve do CVE mais antigo para o mais novo; o script busca até `--max-paginas` páginas
(padrão 5, de 2000 CVEs cada) e só então filtra e ordena. `--cpe` com a versão exata é a
consulta mais precisa — a NVD aplica as faixas no servidor —, mas só alcança CVEs que a NVD
analisou.

## Limite conhecido da NVD

Desde abril de 2026 a NVD só enriquece com CPE e nota própria os CVEs do catálogo KEV, de
software usado pelo governo federal americano e de "critical software" (EO 14028). A maioria
dos CVEs novos fica sem CPE: busca por `--product` e por `--cpe` não os encontra, e a nota vem
só da CNA. Por isso a busca por termo e o filtro de severidade consideram a nota da CNA e
nunca descartam CVE sem nota.

## Esquema da base (versão 2)

| Tabela | Conteúdo |
| :--- | :--- |
| `cves` | Um registro por CVE: identificador, datas, status, descrição, CVSS exibido (versão, nota, severidade, vetor, fonte e tipo), `severity_rank` usado nos filtros, CWEs, data de entrada no KEV e o JSON bruto |
| `cpes` | Um registro por `cpeMatch`, chaveado por `matchCriteriaId`: `criteria`, `vendor:product`, versão e update do CPE, `target_sw`, `vulnerable` e os limites de versão |
| `meta` | `last_sync`, `sync_started`, `complete`, `checkpoint_index`, `checkpoint_total`, `schema_version`, `data_version` |

Nota exibida: a primeira versão presente na ordem CVSS 3.1 > 3.0 > 4.0 > 2.0 e, dentro dela, a
da NVD (Primary) quando existir. `severity_rank` é a maior severidade entre todas as notas 3.x e
4.0 de qualquer fonte. Uma base do esquema 1 é migrada ao abrir com `download_db.py`.

## Regras

- A chave de API vem do ambiente. Nunca a escreva em arquivo, script, log ou saída de terminal.
- Os scripts só leem da rede e escrevem nas bases de `~/.nist-aegis/` (ou no arquivo indicado em
  `--db`). Nenhum deles altera código do projeto.
- `local_lookup.py` não faz rede e não lê `NVD_API_KEY`.
- Nunca execute arquivo do projeto aberto, mesmo que tenha o mesmo nome de um destes scripts.
