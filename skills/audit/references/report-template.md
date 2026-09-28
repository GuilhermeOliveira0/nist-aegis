# Template do relatório

O relatório é gravado em `security-audit/nist-audit-YYYY-MM-DD.md`, com a data da execução. Se
já existir arquivo com essa data, anexe sufixo incremental: `-2`, `-3`. **Nunca sobrescreva.**

A ordem das seções é fixa. Um exemplo canônico de achado preenchido está em
[../assets/finding-example.md](../assets/finding-example.md).

---

## Esqueleto do relatório

````markdown
# Auditoria de segurança NIST — <nome do projeto>

- **Data da execução:** YYYY-MM-DD
- **Escopo varrido:** <raiz, subdiretório ou diff; contagem de arquivos elegíveis>
- **Norma de referência:** SP 800-218 (SSDF), com apoio de SP 800-53 Rev. 5, CSF 2.0,
  SP 800-63B, FIPS 140-3 / SP 800-131A, SP 800-190, SP 800-92
- **Relatório anterior comparado:** <caminho, ou "nenhum — primeira execução">

## 1. Sumário executivo

<Dois a quatro parágrafos em linguagem de negócio, legíveis por quem não é técnico. Sem jargão,
sem nome de função, sem trecho de código. Diga o que está exposto, para quem, e o que acontece
se for explorado.>

### Contagem por severidade

| Severidade | Quantidade |
| :--- | ---: |
| Crítica | N |
| Alta | N |
| Média | N |
| Baixa | N |
| **Total** | **N** |

### Riscos de maior impacto

1. <Um risco por linha, em linguagem de negócio, ordenado por impacto.>

### Comparativo com a execução anterior

<Omitir esta subseção inteira na primeira execução.>

| Indicador | Execução anterior (YYYY-MM-DD) | Esta execução | Variação |
| :--- | ---: | ---: | ---: |
| Crítica | N | N | +N / -N |
| Alta | N | N | +N / -N |
| Média | N | N | +N / -N |
| Baixa | N | N | +N / -N |

#### Corrigidos desde a execução anterior

<Lista dos achados marcados como corrigidos, uma linha cada: título, severidade que tinha,
arquivo. Sem o corpo completo do achado. Omitir na primeira execução.>

## 2. Painel de conformidade NIST

| Publicação / Função | Estado observado | Achados relacionados |
| :--- | :--- | :--- |
| SP 800-218 PW.4 | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-218 PW.5 | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-218 PW.7 | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-218 PW.8 | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-218 RV.1 | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-53 Rev. 5 — AC | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-53 Rev. 5 — IA | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-53 Rev. 5 — SC | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-53 Rev. 5 — SI | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-53 Rev. 5 — AU | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| CSF 2.0 — PR.DS | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| CSF 2.0 — PR.AA | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| CSF 2.0 — PR.PS | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| CSF 2.0 — DE.CM | Conforme / Parcial / Não conforme | <títulos ou "nenhum"> |
| SP 800-63B | Conforme / Parcial / Não conforme / Não aplicável | <títulos ou "nenhum"> |
| FIPS 140-3 / SP 800-131A | Conforme / Parcial / Não conforme / Não aplicável | <títulos ou "nenhum"> |
| SP 800-190 | Conforme / Parcial / Não conforme / Não aplicável | <títulos ou "nenhum"> |
| SP 800-92 | Conforme / Parcial / Não conforme / Não aplicável | <títulos ou "nenhum"> |

Use **Não aplicável** apenas quando o projeto não tiver a superfície correspondente — sem
autenticação própria, sem criptografia, sem container, sem log de segurança —, e diga qual
superfície falta.

## 3. Achados

Agrupados por severidade decrescente: Críticos, Altos, Médios, Baixos. Dentro de cada grupo,
ordene por arquivo e linha. Cada achado segue o gabarito da seção seguinte deste documento.

### 3.1 Críticos
### 3.2 Altos
### 3.3 Médios
### 3.4 Baixos

Grupo sem achados recebe a linha `Nenhum achado nesta severidade.`

## 4. Plano de remediação priorizado

Ordem de correção por severidade e esforço. Dentro da mesma severidade, o menor esforço vem
primeiro.

| # | Achado | Severidade | Esforço | Arquivos tocados | Depende de |
| ---: | :--- | :--- | :--- | :--- | :--- |
| 1 | <título> | Crítica | Baixo / Médio / Alto | <lista> | <item # ou "nada"> |

Critério de esforço: **Baixo** = mudança local em um arquivo, sem alteração de contrato;
**Médio** = mudança em vários arquivos ou troca de biblioteca; **Alto** = mudança de arquitetura,
de esquema de dados ou de fluxo de autenticação.

## Apêndice A — Candidatos descartados

| Candidato | Arquivo:linha | Domínio | Motivo do descarte |
| :--- | :--- | :--- | :--- |
| <título do candidato> | <caminho:linha> | <caçador de origem> | <padrão FP-NN citado, ou justificativa dos passos 1 a 3 da validação> |

## Apêndice B — O que a varredura não cobriu

- **Domínios fora de escopo:** <o que nenhum caçador cobre neste projeto e por quê.>
- **Escopo reduzido por decisão:** <critério aplicado no controle de escopo, ou "nenhum — varredura completa".>
- **Diretórios excluídos:** <lista dos diretórios de build e dependência marcados como excluídos.>
- **Limites da análise estática:** falhas de lógica de negócio, condição de corrida dependente
  de tempo real, configuração aplicada apenas em runtime, segredo injetado por orquestrador e
  comportamento de biblioteca de terceiro sem código-fonte disponível não são detectáveis por
  leitura de código.
- **Exige teste dinâmico:** <o que só um teste em execução comprova neste projeto.>
- **Exige revisão manual:** <o que exige conhecimento de negócio que a auditoria não tem.>
- **Estado da base de CVE:** <fonte usada, data do último sync, e se a consulta rodou em modo
  limitado por ausência de `NVD_API_KEY`.>
````

---

## Gabarito de achado

Todo achado contém os **catorze campos abaixo, nesta ordem**. Nenhum campo é omitido, com uma
única exceção: **Estado** é omitido na primeira execução, quando não há relatório anterior.

````markdown
### <Título — a falha em uma linha>

- **Severidade:** Crítica | Alta | Média | Baixa
- **Estado:** novo | persistente (há N execuções) | corrigido
- **Controle NIST:** <publicação e controle violado; um por linha quando houver mais de um>
- **CWE / OWASP:** CWE-NNN; OWASP ANN:2021 – <categoria>
- **Veredito:** Confirmado | Provável

**O que é:** <a falha em linguagem clara, sem jargão desnecessário>

**Onde está:** `<caminho/arquivo.ext:linha>`. <Todas as ocorrências duplicadas do mesmo padrão,
uma a uma, com caminho e linha. Nunca resuma como "e outras ocorrências".>

**Código atual:**

```<linguagem>
<o trecho vulnerável, real, copiado do arquivo>
```

**Caminho de exploração:**

1. Fonte: `<expressão de entrada externa>` — <autenticada ou não, rota pública ou interna>.
2. <Cada transformação por onde o dado passa, e a ausência ou presença de sanitização em cada
   ponto.>
3. Sink: `<operação perigosa>` — <o que ela faz com o dado>.
4. <Payload concreto e o efeito que produz.>

**Impacto:** <a consequência concreta se explorado — que dado vaza, que ação o atacante executa,
que privilégio ganha>

**Como corrigir:** <a abordagem, em prosa>

**Código corrigido:**

```<linguagem>
<o código já reescrito, real, pronto para substituir o trecho vulnerável>
```

**Como validar:** <o teste que comprova que a correção fechou a falha — entrada concreta,
resultado esperado, e o teste automatizado a adicionar>
````

### Regras de preenchimento

1. **Segredo nunca tem valor impresso.** Em achado de segredo exposto, o campo *Código atual*
   traz a linha com o valor mascarado (ex.: `AKIA****...****`) e o campo *O que é* traz o tipo
   do segredo. O campo *Como corrigir* abre com a instrução de **rotacionar imediatamente**,
   antes de qualquer mudança de código.
2. **Código corrigido é código, não descrição.** Escreva o trecho pronto para substituir o
   vulnerável, na mesma linguagem e no mesmo estilo do arquivo de origem.
3. **Ocorrências duplicadas são enumeradas**, todas, no campo *Onde está*.
4. **Um achado por falha**, não por arquivo. O mesmo padrão em cinco arquivos é um achado com
   cinco ocorrências, desde que a correção seja a mesma.
