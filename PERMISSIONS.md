# Permissões do plugin `nist`

## O que vale hoje

- **Plugin não distribui regra de permissão.** O `settings.json` na raiz de um plugin aceita só
  as chaves `agent` e `subagentStatusLine`. As regras abaixo são para colar no seu
  `~/.claude/settings.json` ou no `.claude/settings.json` de um projeto seu.
- **Quem restringe de verdade os subagentes é o campo `tools` de cada agente.** Sete agentes só
  têm `Read`, `Grep` e `Glob`; o `redator-relatorio` tem também `Write` e `Edit`; o
  `cacador-dependencias` tem `Bash`, restrito por instrução aos scripts de consulta de CVE.
  `permissionMode` em agente de plugin é ignorado pelo Claude Code, por isso não é usado.
- **Regra `allow` casa o texto do comando como foi escrito.** `~` funciona em regra de Bash
  (o Git Bash expande), mas **não** no Windows PowerShell 5.1, que passa `~` literal para o
  Python. Uma regra `PowerShell(python ~\.claude\...)` pré-aprovava, na prática, um script em
  `<projeto>\~\.claude\...` — dentro do repositório auditado. Por isso as variantes PowerShell
  foram removidas.
- **Removidas em 2026-09-28**, por risco de execução de código ou por contradizer o plugin:
  - as regras com caminho relativo ao projeto (`.claude/skills/cve/scripts/...`): pré-aprovavam
    executar um script que o repositório auditado trouxesse (CWE-426);
  - todas as regras de `download_db.py`: atualizar a base é decisão do usuário (regra 10 da
    skill `audit`);
  - a raiz `~/.claude/plugins/nist/`: a instalação por marketplace fica em
    `~/.claude/plugins/cache/<marketplace>/<plugin>/<versão>/`. Ao escrever regra para esse
    caminho, fixe a versão: `*` no meio de uma regra casa qualquer texto, inclusive `../`.
- **O agente monta o caminho a partir de `${CLAUDE_PLUGIN_ROOT}`**, que vira caminho absoluto
  (no Windows, `C:/Users/<você>/...`) e vai entre aspas. Regras escritas com `~` não casam essa
  forma. Em modo Manual, aprove uma vez por sessão ou acrescente a forma absoluta da sua máquina,
  como nas duas últimas regras `allow` do bloco.
- **As regras `deny` são redutor de acidente, não fronteira.** Casam por prefixo de texto e se
  contornam com facilidade (`py -c`, `node -e`, `iwr`, `irm`, `git -C <dir> commit`).

## Bloco para colar

Troque `<HOME>` pelo seu diretório de usuário com barras normais (ex.: `C:/Users/voce`) para
pré-aprovar a forma absoluta que o agente usa, ou apague essas duas linhas.

```json
{
  "permissions": {
    "allow": [
      "Bash(python ~/.claude/skills/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python ~/.claude/skills/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python3 ~/.claude/skills/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python3 ~/.claude/skills/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python ~/.claude/plugins-src/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python ~/.claude/plugins-src/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python3 ~/.claude/plugins-src/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python3 ~/.claude/plugins-src/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python \"<HOME>/.claude/skills/nist/skills/cve/scripts/local_lookup.py\" *)",
      "Bash(python \"<HOME>/.claude/skills/nist/skills/cve/scripts/nvd_lookup.py\" *)"
    ],
    "deny": [
      "Bash(python -c *)",
      "Bash(python3 -c *)",
      "Bash(python -m *)",
      "Bash(python3 -m *)",
      "Bash(pip *)",
      "Bash(pip3 *)",
      "Bash(npm *)",
      "Bash(npx *)",
      "Bash(yarn *)",
      "Bash(pnpm *)",
      "Bash(curl *)",
      "Bash(wget *)",
      "Bash(sh *)",
      "Bash(bash *)",
      "Bash(zsh *)",
      "Bash(cmd *)",
      "Bash(powershell *)",
      "Bash(pwsh *)",
      "Bash(rm *)",
      "Bash(chmod *)",
      "Bash(chown *)",
      "Bash(git commit *)",
      "Bash(git push *)",
      "PowerShell(python -c *)",
      "PowerShell(python3 -c *)",
      "PowerShell(python -m *)",
      "PowerShell(python3 -m *)",
      "PowerShell(pip *)",
      "PowerShell(pip3 *)",
      "PowerShell(npm *)",
      "PowerShell(npx *)",
      "PowerShell(yarn *)",
      "PowerShell(pnpm *)",
      "PowerShell(curl *)",
      "PowerShell(Invoke-WebRequest *)",
      "PowerShell(Invoke-RestMethod *)",
      "PowerShell(wget *)",
      "PowerShell(Remove-Item *)",
      "PowerShell(git commit *)",
      "PowerShell(git push *)",
      "Read(./.env)",
      "Read(./.env.*)"
    ]
  }
}
```

São 10 regras `allow` (8 com `~` para as raízes `~/.claude/skills/nist/` e
`~/.claude/plugins-src/nist/`, mais 2 na forma absoluta) e 42 regras `deny`. Se você já colou a
versão anterior deste bloco, **apague as regras relativas a `.claude/skills/cve/`, as de
PowerShell com `~` e as de `download_db.py`**.

## Histórico da investigação

Resumo do que foi testado em 2026-08-31, no Claude Code 2.1.250:

- **As regras Bash com `~` casam.** Em Manual mode (`claude --permission-mode default`), com o
  workspace confiado, `python ~/.claude/skills/nist/skills/cve/scripts/local_lookup.py --db
  ~/.nvd/nvd.sqlite --stats` executou, e `python ~/.claude/skills/nist/skills/cve/scripts/nvd_common.py`
  foi negado: mesmo interpretador e diretório, só o script muda.
- **Auto mode.** Uma regra `allow` que casa resolve antes do classificador; sem regra, o
  classificador decide, e leitura e edição dentro do diretório de trabalho são aprovadas. Por
  isso, em auto mode, o efeito de uma regra `allow` não é observável de fora.
- **Aviso de workspace não confiado em `claude -p`.** `Ignoring N permissions.allow entries`
  vinha de a chave do projeto em `~/.claude.json` estar gravada com contrabarra, enquanto a
  sessão não interativa consultava a forma com barra normal. Aceitar o diálogo de confiança numa
  sessão interativa criou a segunda forma, e o aviso sumiu.
- **`${CLAUDE_PLUGIN_ROOT}` não é substituído em regra de permissão**, só em conteúdo de skill, de
  agente e de hook. Por isso as raízes vão escritas por extenso.
