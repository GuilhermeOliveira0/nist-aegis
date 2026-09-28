# Estado das regras de permissão

Investigado em 2026-08-31, Claude Code 2.1.250. Não refaça: o resultado está aqui.

**Modo testado: auto mode.** Nenhum `defaultMode` em `.claude/settings.json`,
`.claude/settings.local.json` ou `~/.claude/settings.json`; a documentação diz que auto mode é o
inicial em Pro, Max e Team, e o harness da sessão confirmou. Ordem em auto mode, primeiro passo
que casa vence: (1) `allow`, `ask` e `deny` resolvem imediatamente; (2) leitura e edições no
diretório de trabalho são auto-aprovadas; (3) o resto vai ao classificador, um segundo modelo que
decide em lugar do usuário. Entre regras: `deny` → `ask` → `allow`, primeira correspondência
vence, especificidade não altera a ordem, e `deny` bloqueia em todo modo — inclusive
`bypassPermissions`.

**Comprovadamente eficazes — as 42 `deny`.** `Bash(python -c *)` bloqueou
`python -c "import os; ..."` com erro explícito de permissão. Para teste de ambiente use
`[ -n "$NVD_API_KEY" ]` em shell: o idioma `python -c` está barrado por projeto.

**Não comprováveis por observação — as 21 `allow`.** Em auto mode, um comando fora da allowlist
(`python --version`) roda sem prompt igual a um dentro dela
(`python .../download_db.py --help`): o primeiro é aprovado pelo classificador no passo 2 ou 3, o
segundo pela regra no passo 1. O resultado observável é idêntico, então a eficácia das `allow` é
indistinguível aqui. Não são inúteis — em Manual mode são o que evita o prompt, e no passo 1
dispensam a ida ao classificador. Mantidas por isso.

**Válidas mas inertes nesta máquina.** As variantes `python3`: aqui `python3` é o stub da
Microsoft Store e não executa; valem em Linux e macOS. (O parágrafo original dizia também que
`~/.claude/skills/` estava vazio e que a skill vivia no projeto. **Isso deixou de valer**: o
plugin foi instalado como `nist@skills-dir` em `~/.claude/skills/nist/` e as cópias de projeto
foram removidas. Ver o adendo no fim deste arquivo.)

**Corrigido nesta investigação.** Três variantes `PowerShell` com contrabarra. As anteriores
usavam barra normal, e no Windows o comando sai como `python .claude\skills\...`, que não casa
com o prefixo literal `python .claude/skills/...` — a regra casa a string como foi escrita.

**Indeterminado — resolvido, ver "Fecho" no fim deste arquivo.** Ao entrar em auto mode o Claude Code descarta regras `allow` amplas que
concedem execução arbitrária, e a lista inclui "interpretadores com coringa, como `Bash(python*)`".
Nossas regras são `Bash(python <caminho-literal-do-script> *)`, com coringa só na cauda de
argumentos, o que as põe do lado de "regras estreitas como `Bash(npm test)` seguem valendo". Não
foi possível confirmar de qual lado o heurístico interno as coloca: a documentação só exemplifica
a forma sem espaço, e o resultado não é observável em auto mode. Teste em Manual mode se importar.

## Bloco pronto para colar

Plugins não declaram permissões: a documentação diz que o `settings.json` da raiz do plugin
aceita só as chaves `agent` e `subagentStatusLine`. Então as regras não viajam com o plugin —
cole o bloco abaixo em `~/.claude/settings.json` ou no `settings.json` do projeto.

As regras `allow` cobrem quatro raízes, nesta ordem: instalação `@skills-dir`
(`~/.claude/skills/nist/`, que é a usada hoje), instalação por marketplace
(`~/.claude/plugins/nist/`), fonte de desenvolvimento (`~/.claude/plugins-src/nist/`) e
skill instalada no projeto auditado (`.claude/skills/cve/`). A primeira faltava na versão
anterior deste bloco, que cobria só três raízes e portanto não cobria o caminho real.
Variantes com barra normal para Bash em Linux e macOS, e com contrabarra para PowerShell no
Windows. `${CLAUDE_PLUGIN_ROOT}` **não** é substituído em regras de permissão — só em conteúdo
de skill e de agente —, por isso as raízes vão escritas por extenso. Se o plugin ficar em outro
caminho, ajuste a raiz.

As 42 regras `deny` são as mesmas da investigação anterior, sem nenhuma alteração.

```json
{
  "permissions": {
    "allow": [
      "Bash(python ~/.claude/skills/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python ~/.claude/skills/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python ~/.claude/skills/nist/skills/cve/scripts/download_db.py *)",
      "Bash(python3 ~/.claude/skills/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python3 ~/.claude/skills/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python3 ~/.claude/skills/nist/skills/cve/scripts/download_db.py *)",
      "Bash(python ~/.claude/plugins/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python ~/.claude/plugins/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python ~/.claude/plugins/nist/skills/cve/scripts/download_db.py *)",
      "Bash(python3 ~/.claude/plugins/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python3 ~/.claude/plugins/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python3 ~/.claude/plugins/nist/skills/cve/scripts/download_db.py *)",
      "Bash(python ~/.claude/plugins-src/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python ~/.claude/plugins-src/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python ~/.claude/plugins-src/nist/skills/cve/scripts/download_db.py *)",
      "Bash(python3 ~/.claude/plugins-src/nist/skills/cve/scripts/local_lookup.py *)",
      "Bash(python3 ~/.claude/plugins-src/nist/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python3 ~/.claude/plugins-src/nist/skills/cve/scripts/download_db.py *)",
      "Bash(python .claude/skills/cve/scripts/local_lookup.py *)",
      "Bash(python .claude/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python .claude/skills/cve/scripts/download_db.py *)",
      "Bash(python3 .claude/skills/cve/scripts/local_lookup.py *)",
      "Bash(python3 .claude/skills/cve/scripts/nvd_lookup.py *)",
      "Bash(python3 .claude/skills/cve/scripts/download_db.py *)",
      "PowerShell(python ~\\.claude\\skills\\nist\\skills\\cve\\scripts\\local_lookup.py *)",
      "PowerShell(python ~\\.claude\\skills\\nist\\skills\\cve\\scripts\\nvd_lookup.py *)",
      "PowerShell(python ~\\.claude\\skills\\nist\\skills\\cve\\scripts\\download_db.py *)",
      "PowerShell(python ~\\.claude\\plugins\\nist\\skills\\cve\\scripts\\local_lookup.py *)",
      "PowerShell(python ~\\.claude\\plugins\\nist\\skills\\cve\\scripts\\nvd_lookup.py *)",
      "PowerShell(python ~\\.claude\\plugins\\nist\\skills\\cve\\scripts\\download_db.py *)",
      "PowerShell(python ~\\.claude\\plugins-src\\nist\\skills\\cve\\scripts\\local_lookup.py *)",
      "PowerShell(python ~\\.claude\\plugins-src\\nist\\skills\\cve\\scripts\\nvd_lookup.py *)",
      "PowerShell(python ~\\.claude\\plugins-src\\nist\\skills\\cve\\scripts\\download_db.py *)",
      "PowerShell(python .claude\\skills\\cve\\scripts\\local_lookup.py *)",
      "PowerShell(python .claude\\skills\\cve\\scripts\\nvd_lookup.py *)",
      "PowerShell(python .claude\\skills\\cve\\scripts\\download_db.py *)"
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

## Adendo do empacotamento — confiança do workspace

Ao carregar o plugin com `--plugin-dir` numa sessão headless, o Claude Code emitiu:

`Ignoring 21 permissions.allow entries from .claude/settings.json: this workspace has not been
trusted.`

**Correção.** A conclusão que eu havia tirado desse aviso era mais ampla do que os fatos
suportam. Inspecionando `~/.claude.json`, a entrada
`projects["C:\Users\Windows\Documents\skill-security"]` **já estava** com
`hasTrustDialogAccepted: true`. O aviso aparece só nas sessões `claude -p` aninhadas, e a
mensagem cita a chave na forma com **barra normal** (`C:/Users/...`), diferente da forma com
contrabarra que está gravada. O sintoma é de descasamento na forma da chave, não de ausência de
confiança: na sessão interativa as regras `allow` provavelmente estavam ativas todo o tempo.

A documentação sustenta a distinção: `permissions.allow` e `additionalDirectories` de um
`.claude/settings.json` de projeto só valem depois do diálogo de confiança, enquanto `deny` e
`ask` valem de imediato; e o diálogo aparece apenas em sessão interativa — "a `claude -p` run or
an SDK session never shows it". A confiança é gravada por diretório (ou pela raiz do repositório
git, quando há uma), não por conta.

Procedimento manual, que é o documentado para sessão não interativa: definir
`projects["<caminho>"].hasTrustDialogAccepted` como `true` em `~/.claude.json`, usando a forma de
caminho que o aviso citar. Não foi executado aqui: o classificador do auto mode bloqueou a
escrita em `~/.claude.json`, e com razão — é configuração global e concessão de confiança, uma
decisão do usuário, não do agente.

**Evidência nova sobre o auto mode.** Nesta sessão o classificador bloqueou tanto a escrita em
`~/.claude.json` quanto a edição de `.claude/settings.json`, e liberou as remoções de arquivo da
limpeza. Isso confirma que o classificador é o portão ativo e que escrita em caminho protegido
vai a ele mesmo quando existe regra `allow` — como a documentação afirma. **Não** resolve se
`Bash(python <script> *)` sobrevive ao heurístico que descarta interpretadores com coringa: com
o classificador aprovando comandos benignos de todo modo, o resultado continua indistinguível em
auto mode. O teste discriminante é Manual mode (`claude --permission-mode default`) depois de
confiar o workspace: ali, regra que não casa gera prompt.

## Fecho — 2026-08-31, com o workspace confiado

O trust foi concedido pelo diálogo interativo. Três coisas ficaram resolvidas.

**1. O aviso de trust era descasamento na forma da chave.** Antes de aceitar o diálogo,
`~/.claude.json` já tinha `projects["C:\Users\...\skill-security"].hasTrustDialogAccepted: true`,
com contrabarra. Aceitar o diálogo **criou uma segunda entrada**, com barra normal, e o aviso
`Ignoring N permissions.allow entries` desapareceu das sessões `claude -p`. Hipótese confirmada:
faltava a chave na forma que a sessão não interativa consulta, não a confiança em si.

**2. As regras `allow` são comprovadamente eficazes.** Isso encerra o que a investigação
anterior classificou como "não comprovável por observação". O par discriminante, em Manual mode
(`claude --permission-mode default`), com o workspace confiado:

| Comando | Tem regra `allow`? | Resultado |
| :--- | :--- | :--- |
| `python ~/.claude/skills/nist/skills/cve/scripts/local_lookup.py --db ~/.nvd/nvd.sqlite --stats` | Sim | Executou |
| `python ~/.claude/skills/nist/skills/cve/scripts/nvd_common.py` | Não | Negado |

Mesmo interpretador, mesmo diretório, só o script difere. Fica provado que
`Bash(python <caminho-literal-do-script> *)` casa, que o `~` casa como escrito, e que em Manual
mode a regra é o que separa executar de ser negado. O que faltava não era outra regra: era o
trust e o modo certo para testar.

**3. O descarte de `allow` em auto mode segue não observável, e agora é irrelevante.**
`claude --debug` não registra quais regras foram descartadas ao entrar em auto mode, então não há
como ver de fora se `Bash(python <script> *)` é classificada como interpretador com coringa. Mas
a consequência prática é nula: em Manual mode as regras funcionam, provado acima; em auto mode o
comando roda de todo modo, seja pela regra no passo 1, seja pelo classificador no passo 3. O item
sai de "indeterminado com consequência" para "detalhe interno sem efeito observável".

**Observação lateral, sem garantia de causalidade.** Com o workspace não confiado, o classificador
negou a edição de `.claude/settings.json` e a escrita em `~/.claude.json`; com o workspace
confiado, a mesma edição de `.claude/settings.json` passou. São dois pontos e o classificador é um
modelo, então trate como comportamento observado, não como regra. A escrita em `~/.claude.json`
não foi retentada: concessão de confiança é decisão do usuário.
