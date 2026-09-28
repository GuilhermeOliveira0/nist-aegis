# Changelog

## 1.1.0 — 2026-09-28

### Segurança da própria ferramenta

- Os scripts de CVE só rodam de dentro do plugin (`${CLAUDE_PLUGIN_ROOT}`); saíram os caminhos
  alternativos que executariam um script trazido pelo repositório auditado (CWE-426), e as
  regras `allow` relativas ao projeto, de PowerShell com `~` e de `download_db.py`.
- `/nist:cve` usa `${CLAUDE_SKILL_DIR}` em vez de `scripts/` relativo ao projeto aberto.
- Os subagentes são invocados sempre como `nist:<nome>`: um agente do projeto com o mesmo nome
  curto tinha prioridade e podia suprimir todos os achados.
- Regra anti-injeção e `omitClaudeMd` nos nove agentes; o conteúdo que tenta dirigir a auditoria
  é registrado no Apêndice B.
- Nenhum subagente executa comando: o `cacador-dependencias` perdeu o `Bash` e o redator perdeu o
  `Edit`. O git roda endurecido para repositório não confiável.

### Dependências

- Novo `sca_scan.py`: lê lockfiles de npm, PyPI, Go, crates.io, Packagist, RubyGems, NuGet e
  Maven e casa pacote e versão exata no OSV, com nota, CWE e KEV da base NVD local, cadeia até o
  pacote direto, versões corrigidas e pacote malicioso conhecido (`MAL-*`).
- Scripts da NVD: saída em UTF-8, códigos de saída distintos, faixas de versão por
  `matchCriteriaId`, campo `vulnerable`, CVSS 4.0, rejeitados fora, CVE sem nota nunca filtrado,
  busca por palavra inteira com aviso de truncamento, paginação completa na API, download que não
  se marca completo em erro, esquema 2 com migração e `--reindex`.

### Auditoria

- Novo `inventario.py`: contagem exata de arquivos elegíveis, arquivos versionados, escopo por
  diff, varredura de segredos mascarada em todos os arquivos de texto, configuração de agente de
  IA e Unicode oculto no repositório.
- Validador com conferência de evidência, trilha para achado sem fluxo de dado (constante,
  configuração, ausência de controle, segredo, dependência) e contagem de conservação.
- Tabela canônica categoria → CWE / OWASP 2025 / SSDF / SP 800-53 / CSF 2.0 / linha do painel.
- Painel sem "Conforme": estados "desvio", "sem desvio no escopo analisado", "não avaliado" e
  "não aplicável", com regra explícita.
- Comparação entre execuções só na interseção dos escopos; "corrigido" só quando o trecho sumiu;
  JSON ao lado do relatório.
- Normas: SP 800-63B-4 (senha de 15 caracteres como fator único, composição proibida), Argon2id,
  scrypt e bcrypt como não FIPS, OWASP Top 10:2025, controles SP 800-53 mais precisos.
- Severidade: a Regra 3 não rebaixa IDOR, escalonamento, CSRF nem fixação de sessão; base de CVE
  em dependência pela nota publicada, piso de Alta para CVE no KEV, pacote malicioso Crítica.
- Categorias novas: CSRF, injeção de código no servidor, pipeline de CI/CD, segredo ou dado
  sensível em log, pacote malicioso. C/C++ declarado fora de escopo.
- A auditoria não para mais para perguntar sobre dependências não instaladas.

### Testes

- `tests/`: 52 testes unitários dos scripts, só biblioteca padrão.
- `evals/`: suíte de regressão para `claude plugin eval`, com um app vulnerável e três
  armadilhas de injeção.

## 1.0.0 — 2026-09-28

Versão inicial publicada.
