# nist

Auditoria de código-fonte contra frameworks NIST por nove subagentes especializados, com base
local de CVEs da NVD. SP 800-218 (SSDF) é a espinha dorsal; SP 800-53 Rev. 5, CSF 2.0,
SP 800-63B, FIPS 140-3 / SP 800-131A, SP 800-190 e SP 800-92 entram como apoio por domínio. Cada
achado cita o controle violado e correlaciona com CWE e OWASP Top 10 2021.

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
- `avaliador-severidade` — rubrica CVSS 3.1 e cinco regras de desempate. Único que atribui severidade.
- `redator-relatorio` — grava `security-audit/nist-audit-YYYY-MM-DD.md` e compara com a execução anterior.

## Instalação

Carregar sem instalar, por diretório ou por zip:

```bash
claude --plugin-dir ~/.claude/plugins-src/nist
claude --plugin-dir ~/.claude/plugins-src/nist.zip
```

Para instalação permanente sem marketplace, rode `cp -r ~/.claude/plugins-src/nist
~/.claude/skills/nist` — de lá o plugin carrega sozinho na próxima sessão. Depois de alterar
qualquer arquivo do plugin, rode `/reload-plugins` para recarregar sem reiniciar.

## Uso

```
/nist:audit
/nist:cve
```

## Pré-requisito: base de CVEs

`cacador-dependencias` e `/nist:cve` consultam `~/.nvd/nvd.sqlite`. Sem a base a auditoria roda e
registra `modo_consulta: sem base de CVE` no Apêndice B. Download completo, incremental e estado —
384.682 CVEs, cerca de 2,8 GB:

```bash
python ~/.claude/plugins-src/nist/skills/cve/scripts/download_db.py --db ~/.nvd/nvd.sqlite
python ~/.claude/plugins-src/nist/skills/cve/scripts/download_db.py --db ~/.nvd/nvd.sqlite --update
python ~/.claude/plugins-src/nist/skills/cve/scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --stats
```

O download grava checkpoint a cada página: interrompido, rode o mesmo comando de novo e ele
retoma. `--stats` marca a base como desatualizada depois de 7 dias — rode o `--update` aí.

## Pré-requisito: NVD_API_KEY

Lida da variável de ambiente, nunca gravada em arquivo. Sem chave o rate limit da NVD é 5
requisições por 30 s e o download completo leva 15-20 minutos; com chave são 50 por 30 s.

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
`~/.claude/settings.json` ou no do projeto: 27 regras `allow` nas três raízes possíveis, 42
regras `deny`, o modo sob o qual foram testadas e o que ficou indeterminado.
