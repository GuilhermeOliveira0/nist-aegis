# Changelog

## 1.2.0 — 2026-09-29

### Base OSV local: nada sai da máquina

- Novo `download_osv.py`: baixa o arquivo público de cada ecossistema (npm, PyPI, Go, Maven,
  crates.io, Packagist, RubyGems, NuGet; cerca de 300 MB compactados), confere o MD5 publicado
  pelo Google Cloud Storage, importa numa transação por ecossistema e apaga o arquivo. `--update`
  baixa só os registros alterados (pela `modified_id.csv` pública); com mais de 2000, baixa o
  arquivo do ecossistema de novo. Falha num registro não avança o corte: o próximo `--update`
  tenta de novo.
- Novo `osv_versions.py`: comparação de versão pela regra de cada ecossistema — SemVer 2.0 (npm,
  Go, crates.io), PEP 440 (PyPI), ComparableVersion (Maven), Gem::Version (RubyGems),
  NuGetVersion e version_compare (Composer) — e o algoritmo de faixas da especificação do OSV.
  Versão ou faixa que o comparador não reconhece sai como "não avaliada", nunca como segura.
- Novo `osv_local.py`: espelho SQLite e consulta por pacote, com o mesmo formato de registro da
  API.
- `sca_scan.py --osv-local`: consulta na base local, sem rede. O JSON ganhou `consulta.modo`,
  `consulta.nao_avaliados` e `base_osv` (data e idade de cada ecossistema); base com mais de 7
  dias ou ecossistema ausente gera aviso em `limites` com o comando para resolver.
- `/nist:audit` usa a base local por padrão. `--online` volta à API; `--offline` desliga a
  consulta. Sem a base, a auditoria segue sem consulta de vulnerabilidade e mostra o comando de
  download — nunca o roda.

### Bases numa pasta só

- `~/.nist-aegis/bases/` guarda `osv.sqlite` e `nvd.sqlite`; `~/.nist-aegis/downloads/`, os
  arquivos em trânsito. `NIST_AEGIS_HOME` troca a pasta.
- `--db` ficou opcional em `download_db.py`, `local_lookup.py` e `sca_scan.py`. A NVD em
  `~/.nvd/nvd.sqlite` continua sendo encontrada enquanto não houver uma em `bases/`.

### Testes

- 41 testes novos (104 no total): as sequências de ordem das especificações de cada
  ecossistema, a avaliação de faixa, importação e reimportação, zip corrompido, MD5 errado ou
  ausente, atualização incremental com e sem falha, e o `sca_scan` no modo local com a rede
  proibida.

## 1.1.1 — 2026-09-29

### Segurança da própria ferramenta

- `inventario.py`: o git não faz mais o fetch preguiçoso de partial clone (`GIT_NO_LAZY_FETCH`,
  `protocol.allow=never`). Um repositório com objeto ausente e `core.sshCommand` próprio fazia o
  `--diff` executar esse comando.
- `inventario.py`: o executável do git é resolvido pelo PATH, recusando entrada relativa e
  qualquer caminho dentro da raiz auditada (um `git.exe` plantado no repositório).
- Os dois scripts não seguem link simbólico e só leem arquivo comum; o `sca_scan.py` ganhou teto
  de 64 MB por arquivo. Os links aparecem em `links_simbolicos` no inventário.
- `--subdiretorio` conferido por caminho real: `../repo2` não passa mais quando a raiz é `repo`.

### Privacidade

- Usuário, senha e token de URL de origem (npm, yarn, pnpm, Cargo, Composer, Gemfile) são
  removidos antes de gravar o `sca.json`, que os agentes leem.
- O que não vai ao OSV vale para todos os ecossistemas: pacote declarado com fonte fora do
  registro público, escopo npm com registro próprio no `.npmrc` ou no `.yarnrc.yml` (lido agora),
  pacote de yarn e pnpm vindo de registro privado (a origem passou a ser lida), membro de
  workspace npm, pacote de pasta local do Poetry, módulo Go coberto por
  `GOPRIVATE`/`GONOPROXY`/`GONOSUMDB`, versão que é URL ou caminho e nome fora do formato.
- `/nist:audit` aceita `--nao-enviar <regex>`.

### Correções

- Lockfile malformado ou hostil (tipo inesperado, aninhamento que estoura a recursão) vira erro
  registrado em `erros` e o scan segue; antes, derrubava o `sca_scan.py` sem gravar o JSON.
- Segredo sem aspas em arquivo de configuração (`.env`, YAML, INI, properties, TOML) passa a ser
  detectado, mascarado como os demais; referência (`$VAR`, `${VAR}`, `ENC[...]`) e número não.
- Número de linha dos segredos e do Unicode oculto conta só `\n`, como o Read.

### Testes

- 11 testes novos (63 no total), entre eles o ataque de partial clone reproduzido contra um
  repositório real, a captura do corpo exato enviado ao OSV e lockfiles malformados de sete
  formatos.

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
