# nist-aegis

Plugin `nist` para Claude Code: auditoria de código-fonte guiada por NIST, com nove subagentes
especializados, inventário determinístico do projeto e consulta de vulnerabilidades por pacote e
versão. SP 800-218 (SSDF) é a espinha dorsal; SP 800-53 Rev. 5, CSF 2.0, SP 800-63B-4,
FIPS 140-3 / SP 800-131A, SP 800-190 e SP 800-92 entram como apoio por domínio. Cada achado cita
o controle violado e correlaciona com CWE e OWASP Top 10:2025.

> **Aviso.** Projeto independente, sem afiliação com o NIST e sem endosso dele. O relatório
> aponta desvios encontrados no código; ele não certifica conformidade com nenhuma publicação do
> NIST.
>
> This product uses data from the NVD API but is not endorsed or certified by the NVD.

## Como funciona

`/nist:audit` orquestra a auditoria completa:

1. **Inventário determinístico** (`inventario.py`): contagem exata de arquivos, o que está
   versionado no git, infraestrutura, pipelines, segredos candidatos já mascarados e configuração
   de agente de IA no repositório.
2. **Vulnerabilidades em dependências** (`sca_scan.py`): lockfiles casados por pacote e versão
   exata na base OSV local, sem rede, com nota, CWE e KEV da base NVD local.
3. **Reconhecimento**, **cinco caçadores de domínio em paralelo**, **validação de falso
   positivo**, **triagem de severidade** e **relatório** em `security-audit/`, com um JSON ao lado
   para comparar execuções.

`/nist:cve` consulta vulnerabilidades de dependências e CVEs na base local ou na API da NVD.

## Os nove subagentes

- `mapeador-projeto` — stack, pontos de entrada, autenticação global, fronteiras de confiança, superfícies.
- `cacador-injecao` — SQL, NoSQL, comando de SO, path traversal, SSTI, XSS, desserialização, XXE, SSRF, open redirect, LDAP, CRLF, injeção de código no servidor.
- `cacador-login-permissao` — autenticação ausente, IDOR, escalonamento, senha (SP 800-63B-4), sessão, JWT, cookie, CSRF, fixação de sessão.
- `cacador-cripto-segredos` — algoritmo proibido, chave curta, ECB, IV estático, PRNG fraco, salt, segredo hardcoded, TLS, comparação não constante, segredo em log.
- `cacador-config-infra` — container, imagem sem pin, segredo em imagem ou IaC, depurador exposto, CORS, headers, debug, stack trace, bucket público, IaC, pipeline de CI/CD.
- `cacador-dependencias` — vulnerabilidade em dependência direta e transitiva, pacote malicioso, versão sem pin, lockfile ausente, fonte fora do registro, abandonada, licença.
- `validador-falsos-positivos` — confere a evidência, valida com ou sem fluxo de dado, emite veredito.
- `avaliador-severidade` — rubrica com faixas CVSS 3.1 e cinco regras de desempate. Único que atribui severidade.
- `redator-relatorio` — grava o relatório e o JSON e compara com a execução anterior.

## Instalação

Pelo marketplace deste repositório:

```bash
claude plugin marketplace add GuilhermeOliveira0/nist-aegis
claude plugin install nist@nist-aegis
```

Ou clone e carregue sem instalar:

```bash
git clone https://github.com/GuilhermeOliveira0/nist-aegis.git
claude --plugin-dir ./nist-aegis
```

`--plugin-dir` também aceita um `.zip` do plugin. Para instalação permanente sem marketplace,
copie a pasta para `~/.claude/skills/nist`. Depois de alterar qualquer arquivo do plugin, rode
`/reload-plugins`.

## Primeiros passos

1. **Instale o plugin** (seção anterior) e confira que tem Python 3.11 ou superior.
2. **Baixe a base OSV uma vez** (cerca de 300 MB). Sem ela, a auditoria roda, mas sem consulta de
   vulnerabilidade em dependência:

   ```bash
   python <pasta-do-plugin>/skills/cve/scripts/download_osv.py
   ```

   `<pasta-do-plugin>` é onde o plugin ficou: `~/.claude/skills/nist` na cópia manual, ou
   `~/.claude/plugins/cache/nist-aegis/nist/<versão>` pelo marketplace. A base da NVD é opcional
   (seção [Bases locais](#bases-locais)).
3. **Abra o Claude Code na pasta do projeto que vai auditar.** A auditoria usa a pasta de
   trabalho da sessão como raiz.
4. **Rode `/nist:audit`.** Na primeira vez o Claude Code pede permissão para os scripts do plugin
   (`inventario.py`, `sca_scan.py`, `local_lookup.py`); aprove.
5. **Leia o relatório** em `security-audit/nist-audit-AAAA-MM-DD.md`.
6. **De tempos em tempos**, atualize a base: `download_osv.py --update` baixa só o que mudou. O
   relatório avisa quando a base passa de 7 dias.

## Uso

```
/nist:audit
/nist:audit src/api
/nist:audit --diff main
/nist:audit --fips --relatorio security-audit/auditoria.md
/nist:audit --online
/nist:cve
```

Por padrão a consulta de vulnerabilidades roda na base OSV local. `--online` consulta a API do
OSV; `--offline` não consulta nada e entrega só o inventário de dependências.

Acima de 500 arquivos elegíveis a auditoria para e pergunta: varrer tudo, só um subdiretório ou
só o diff contra uma branch base.

## O que você recebe

Dois arquivos novos em `security-audit/` do projeto auditado — nunca sobrescreve um existente;
no mesmo dia, ganha sufixo `-2`, `-3`:

- **`nist-audit-AAAA-MM-DD.md`**, o relatório:
  1. sumário executivo, com a contagem por severidade, os riscos de maior impacto e o comparativo
     com a execução anterior;
  2. painel de conformidade por publicação NIST (desvio, sem desvio no escopo, não avaliado, não
     aplicável — nunca "conforme");
  3. achados por severidade, cada um com arquivo, linha, trecho, caminho de exploração, controle
     NIST, CWE, OWASP e correção;
  4. plano de remediação priorizado;
  5. Apêndice A com os candidatos descartados como falso positivo e o motivo; Apêndice B com o
     que a varredura não cobriu.
- **`nist-audit-AAAA-MM-DD.json`**, com os mesmos achados, usado para comparar a próxima execução.

Na conversa aparece só um resumo: os caminhos, a contagem, os críticos em uma linha, o que não
foi verificado e as tentativas de injeção de prompt encontradas. Segredo sai sempre mascarado.

## Modelo, esforço e custo

Os subagentes herdam o modelo da sessão. Use o modelo mais capaz disponível: auditoria é onde um
modelo menor deixa passar falha ou gera falso positivo. `validador-falsos-positivos` e
`avaliador-severidade` rodam sempre com esforço alto; os demais seguem o esforço da sessão —
alto no uso comum, máximo em projeto crítico.

A auditoria dispara pelo menos nove subagentes. Referência: o projeto de teste do eval, com 7
arquivos, consumiu cerca de 720 mil tokens somando os subagentes e levou uns 40 minutos. Em
projeto grande, `--diff <branch>` ou um subdiretório reduzem o custo.

## Privacidade

- **Segredos** são procurados por script, e o valor sai mascarado antes de qualquer agente ver o
  resultado. O valor ainda aparece nas leituras de arquivo que ficam no histórico da sessão:
  para garantia total, audite em ambiente descartável.
- **Dependências**: por padrão, nada sai da máquina — a consulta roda na base OSV local. Só com
  `--online` o nome, o ecossistema e a versão dos pacotes públicos vão para api.osv.dev; mesmo
  assim não é enviado, em nenhum ecossistema, o que o projeto declara com fonte privada (git, URL,
  caminho local, índice ou registro próprio, escopo npm do `.npmrc` ou do `.yarnrc.yml`), módulo
  Go coberto pelo seu `GOPRIVATE`, membro de workspace nem nome que case `--nao-enviar`.
  Usuário, senha e token de URL de origem são removidos antes de gravar o resultado.
  `--offline` não faz rede nenhuma.
- **Relatório**: fica em `security-audit/`, que ganha um `.gitignore` próprio com `*`. Se o seu
  Dockerfile faz `COPY . .`, exclua `security-audit/` no `.dockerignore`.

## Auditar código de terceiros

O plugin nunca executa arquivo do projeto auditado e trata o conteúdo dele como dado, não como
instrução. Mesmo assim, o Claude Code carrega configuração do projeto quando você confia na
pasta. Antes de auditar um repositório que não é seu:

1. Audite um clone novo, feito a partir da URL de origem — não uma pasta recebida já com `.git`
   dentro, que pode trazer configuração de git maliciosa.
2. Antes de aceitar o diálogo de confiança, inspecione `.claude/`, `.mcp.json`, `CLAUDE.md` e
   `AGENTS.md` do projeto: hooks, servidores MCP e agentes do projeto passam a valer depois dele.
3. Prefira rodar a auditoria dentro de um container ou de uma VM.

## Bases locais

As duas bases ficam juntas numa pasta só (`NIST_AEGIS_HOME` troca o lugar):

```
~/.nist-aegis/
├── bases/
│   ├── osv.sqlite     vulnerabilidades por pacote e versão (download_osv.py)
│   └── nvd.sqlite     nota, CWE e KEV de cada CVE (download_db.py)
└── downloads/         arquivos do OSV em trânsito, apagados depois da importação
```

A auditoria nunca baixa nem atualiza uma base por conta própria: ela avisa e mostra o comando.

### OSV (recomendada)

Sem ela, a auditoria roda sem consulta de vulnerabilidade em dependência, a menos que você use
`--online`. Download de npm, PyPI, Go, Maven, crates.io, Packagist, RubyGems e NuGet (cerca de
300 MB compactados), com MD5 conferido; a atualização baixa só os registros alterados:

```bash
python <pasta-do-plugin>/skills/cve/scripts/download_osv.py
python <pasta-do-plugin>/skills/cve/scripts/download_osv.py --update
python <pasta-do-plugin>/skills/cve/scripts/download_osv.py --stats
```

O download é o mesmo arquivo público para qualquer pessoa: não revela o que você audita. A
comparação de versão segue a regra de cada ecossistema; versão que o comparador não reconhece sai
como "não avaliada", nunca como "sem vulnerabilidade". Base com mais de 7 dias gera aviso no
relatório. Os dados do OSV vêm de fontes como GitHub Advisory Database, PyPA, Go e RustSec, cada
uma com a própria licença (a maioria CC-BY 4.0).

### NVD (opcional)

Sem ela, a base OSV traz as vulnerabilidades, e a NVD só acrescenta a nota da NVD, o CWE e o KEV.
Download completo (cerca de 400 mil CVEs e 3 GB; pode passar de uma hora), incremental,
reprocessamento local e estado:

```bash
python <pasta-do-plugin>/skills/cve/scripts/download_db.py
python <pasta-do-plugin>/skills/cve/scripts/download_db.py --update
python <pasta-do-plugin>/skills/cve/scripts/download_db.py --reindex
python <pasta-do-plugin>/skills/cve/scripts/local_lookup.py --stats
```

O download grava checkpoint a cada página: interrompido ou com erro da API, rode o mesmo comando
de novo e ele retoma. Uma base criada pela versão 1.0.0 ganha CVSS 4.0, KEV e as faixas de
versão completas com `--reindex`, sem rede. Uma base em `~/.nvd/nvd.sqlite`, de versões
anteriores, continua sendo usada até você movê-la para `~/.nist-aegis/bases/`.

A chave `NVD_API_KEY` é lida da variável de ambiente, nunca gravada em arquivo. Sem chave o rate
limit da NVD é 5 requisições por 30 s; com chave, 50.

```powershell
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "<sua-chave>", "User")
```

```bash
export NVD_API_KEY="<sua-chave>"
```

No Windows, reinicie o Claude Code depois de gravar: o processo em execução não herda a variável.

## Requisitos

Python 3.11 ou superior para os scripts, só com a biblioteca padrão. Git é opcional: sem ele,
o inventário não sabe o que está versionado.

## Testes

```bash
python tests/test_cve_scripts.py
python tests/test_sca_scan.py
python tests/test_inventario.py
python tests/test_osv_versions.py
python tests/test_osv_local.py
claude plugin eval . --scaffold --runs 1 --ablation none --allow-tools Write --no-publish
```

A suíte de evals audita um app com falhas plantadas e três armadilhas de injeção, e confere que
o segredo não vaza, que nada é escrito fora de `security-audit/` e que nenhum subagente é
chamado pelo nome curto. No Windows nativo o eval não concede `Bash` (falta sandbox), então os
scripts não rodam nele e a auditoria registra isso no Apêndice B.

## Permissões

Plugins não declaram permissões — o `settings.json` da raiz de um plugin aceita só `agent` e
`subagentStatusLine`. `PERMISSIONS.md` traz o bloco JSON para colar em `~/.claude/settings.json`
ou no do projeto, e o que foi removido em 2026-09-28 por risco de execução de código.
