# nist-aegis

Plugin `nist` para Claude Code: auditoria de código-fonte contra frameworks NIST por nove
subagentes especializados, com base local de CVEs da NVD. SP 800-218 (SSDF) é a espinha dorsal;
SP 800-53 Rev. 5, CSF 2.0, SP 800-63B, FIPS 140-3 / SP 800-131A, SP 800-190 e SP 800-92 entram
como apoio por domínio. Cada achado cita o controle violado e correlaciona com CWE e OWASP Top 10.

> **Aviso.** Projeto independente, sem afiliação com o NIST e sem endosso dele. O relatório
> aponta indícios encontrados no código; ele não certifica conformidade com nenhuma publicação
> do NIST.
>
> This product uses data from the NVD API but is not endorsed or certified by the NVD.

`/nist:audit` orquestra a auditoria completa: reconhecimento, cinco caçadores de domínio em
paralelo, validação de falso positivo, triagem de severidade e relatório versionado por data.
`/nist:cve` consulta CVEs na base local ou na API pública da NVD.

## Os nove subagentes

- `mapeador-projeto` — stack, pontos de entrada, fronteiras de confiança, contagem de arquivos elegíveis.
- `cacador-injecao` — SQL, NoSQL, comando de SO, path traversal, SSTI, XSS, desserialização, XXE, SSRF, open redirect, LDAP, CRLF.
- `cacador-login-permissao` — autenticação ausente, IDOR, escalonamento, senha, sessão, JWT, cookie, fixação de sessão.
- `cacador-cripto-segredos` — algoritmo proibido, chave curta, ECB, IV estático, PRNG fraco, salt, segredo hardcoded, TLS, comparação não constante.
- `cacador-config-infra` — Dockerfile, imagem sem pin, segredo em ENV, CORS, headers, debug, stack trace, bucket público, IaC.
- `cacador-dependencias` — CVE conhecido, versão sem pin, dependência abandonada, lockfile ausente, transitiva vulnerável, licença.
- `validador-falsos-positivos` — rastreia fonte até sink, checa mitigação e alcançabilidade, emite veredito.
- `avaliador-severidade` — rubrica com faixas CVSS 3.1 e cinco regras de desempate. Único que atribui severidade.
- `redator-relatorio` — grava `security-audit/nist-audit-YYYY-MM-DD.md` e compara com a execução anterior.

## Instalação

Clone o repositório e carregue o plugin sem instalar:

```bash
git clone https://github.com/GuilhermeOliveira0/nist-aegis.git
claude --plugin-dir ./nist-aegis
```

`--plugin-dir` também aceita um `.zip` do plugin. Para instalação permanente sem marketplace,
copie a pasta para `~/.claude/skills/nist`: de lá o plugin carrega sozinho na próxima sessão.
Depois de alterar qualquer arquivo do plugin, rode `/reload-plugins` para recarregar sem
reiniciar.

## Uso

```
/nist:audit
/nist:cve
```

## Auditar código de terceiros

O plugin nunca executa arquivo do projeto auditado e trata o conteúdo dele como dado, não como
instrução. Mesmo assim, o Claude Code carrega configuração do projeto quando você confia na
pasta. Antes de auditar um repositório que não é seu:

1. Audite um clone novo, feito a partir da URL de origem — não uma pasta recebida já com `.git`
   dentro, que pode trazer configuração de git maliciosa.
2. Antes de aceitar o diálogo de confiança, inspecione `.claude/`, `.mcp.json`, `CLAUDE.md` e
   `AGENTS.md` do projeto: hooks, servidores MCP e agentes do projeto passam a valer depois do
   diálogo.
3. Prefira rodar a auditoria dentro de um container ou de uma VM.

## Pré-requisito: base de CVEs

`cacador-dependencias` e `/nist:cve` consultam `~/.nvd/nvd.sqlite`. Sem a base a auditoria roda e
registra `modo_consulta: sem base de CVE` no Apêndice B. Download completo, incremental e estado
— cerca de 400 mil CVEs e 3 GB; o download completo pode passar de uma hora:

```bash
python <pasta-do-plugin>/skills/cve/scripts/download_db.py --db ~/.nvd/nvd.sqlite
python <pasta-do-plugin>/skills/cve/scripts/download_db.py --db ~/.nvd/nvd.sqlite --update
python <pasta-do-plugin>/skills/cve/scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --stats
```

O download grava checkpoint a cada página: interrompido, rode o mesmo comando de novo e ele
retoma. `--stats` marca a base como desatualizada depois de 7 dias — rode o `--update` aí. A
auditoria nunca baixa nem atualiza a base por conta própria.

## Pré-requisito: NVD_API_KEY

Lida da variável de ambiente, nunca gravada em arquivo. Sem chave o rate limit da NVD é 5
requisições por 30 s; com chave são 50 por 30 s.

```powershell
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "<sua-chave>", "User")
```

```bash
export NVD_API_KEY="<sua-chave>"
```

No Windows, reinicie o Claude Code depois de gravar: o processo em execução não herda a variável.

## Permissões

Plugins não declaram permissões — o `settings.json` da raiz de um plugin aceita só `agent` e
`subagentStatusLine`. `PERMISSIONS.md` traz o bloco JSON pronto para colar em
`~/.claude/settings.json` ou no do projeto: 10 regras `allow` e 42 regras `deny`, e o que foi
removido em 2026-09-28 por risco de execução de código.
