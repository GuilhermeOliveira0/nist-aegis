# Template do relatório

O relatório é gravado em `security-audit/nist-audit-YYYY-MM-DD.md`, com a data da execução, ou
no caminho pedido com `--relatorio`. Se o arquivo já existir, anexe sufixo incremental: `-2`,
`-3`. **Nunca sobrescreva.** Ao lado dele vai um JSON com o mesmo nome e extensão `.json`
(formato no fim desta página), e a pasta `security-audit/` leva um `.gitignore` com `*`.

A ordem das seções é fixa. Um exemplo canônico de achado preenchido está em
[../assets/finding-example.md](../assets/finding-example.md).

---

## Esqueleto do relatório

````markdown
# Auditoria de segurança NIST — <nome do projeto>

- **Data da execução:** YYYY-MM-DD
- **Versão do plugin:** <versão de .claude-plugin/plugin.json>
- **Escopo varrido:** <completo | subdiretório <caminho> | diff <base>...HEAD com N arquivos>; <N arquivos elegíveis, contagem exata do inventário ou aproximada>
- **Norma de referência:** SP 800-218 (SSDF) v1.1, com apoio de SP 800-53 Rev. 5 (release 5.2.0),
  CSF 2.0, SP 800-63B-4, FIPS 140-3 / SP 800-131A Rev. 2, SP 800-190, SP 800-92; OWASP Top 10:2025
- **Relatório anterior comparado:** <caminho, escopo e versão do plugin dele, ou "nenhum — primeira execução", ou o motivo de não comparar>

> Esta auditoria lê código e configuração. Ela aponta desvios encontrados no escopo analisado e
> **não certifica conformidade** com nenhuma publicação do NIST.

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

<Omitir esta subseção inteira na primeira execução e quando não houver relatório comparável.>

| Indicador | Execução anterior (YYYY-MM-DD) | Esta execução | Variação |
| :--- | ---: | ---: | ---: |
| Crítica | N | N | +N / -N |
| Alta | N | N | +N / -N |
| Média | N | N | +N / -N |
| Baixa | N | N | +N / -N |

As contagens comparam só arquivos cobertos pelas duas execuções.

#### Corrigidos desde a execução anterior

<Uma linha cada: título, severidade que tinha, arquivo. Só entra aqui achado cujo trecho
original não existe mais no escopo. Segredo removido entra como "removido do código — rotação e
histórico do git não verificáveis".>

#### Não reencontrados — revalidar

<Uma linha cada: título, severidade que tinha, arquivo:linha onde o trecho original ainda
está. Não conta como corrigido e fica fora da contagem.>

#### Reclassificados como falso positivo

<Achados da execução anterior que agora foram descartados pelo validador, com o motivo do
Apêndice A.>

<Achados anteriores fora do escopo desta execução não são comparados: registre só a quantidade.>

## 2. Painel de conformidade NIST

| Publicação / Função | Estado observado | Achados relacionados | Cobertura |
| :--- | :--- | :--- | :--- |
| SP 800-218 PO.3/PO.5 | <estado> | <títulos ou "nenhum"> | <categorias que alimentam a linha e o status de cada uma> |
| SP 800-218 PW.4 | … | … | … |
| SP 800-218 PW.5 | … | … | … |
| SP 800-218 PW.7 | Não avaliado — prática de processo | nenhum | nenhuma categoria |
| SP 800-218 PW.8 | Não avaliado — prática de processo | nenhum | nenhuma categoria |
| SP 800-218 PW.9 | … | … | … |
| SP 800-218 RV.1 | … | … | … |
| SP 800-53 Rev. 5 — AC | … | … | … |
| SP 800-53 Rev. 5 — IA | … | … | … |
| SP 800-53 Rev. 5 — SC | … | … | … |
| SP 800-53 Rev. 5 — SI | … | … | … |
| SP 800-53 Rev. 5 — AU | … | … | … (AU-2, evento de segurança não registrado, não é caçado) |
| SP 800-53 Rev. 5 — CM | … | … | … |
| SP 800-53 Rev. 5 — RA | … | … | … |
| SP 800-53 Rev. 5 — SR | … | … | … |
| CSF 2.0 — PR.AA | … | … | … |
| CSF 2.0 — PR.DS | … | … | … |
| CSF 2.0 — PR.PS | … | … | … |
| CSF 2.0 — PR.IR | … | … | … |
| CSF 2.0 — ID.RA | … | … | … |
| CSF 2.0 — GV.SC | … | … | … |
| CSF 2.0 — DE.CM | Não avaliado — monitoramento é operação | nenhum | nenhuma categoria |
| SP 800-63B-4 | … | … | … |
| FIPS 140-3 / SP 800-131A | … | … | … (e se o requisito FIPS foi declarado ou presumido ausente) |
| SP 800-190 | … | … | … |
| SP 800-92 | … | … | … |

**Regra dos estados.** As categorias que alimentam cada linha saem da tabela canônica de
`nist-mapping.md`, e o status de cada categoria vem da cobertura devolvida pelos caçadores.

1. **Desvio (maior severidade: X)** — pelo menos um achado validado vem de uma categoria que
   alimenta a linha.
2. **Não avaliado — <motivo>** — nenhuma categoria alimenta a linha, ou alguma que alimenta está
   `nao_verificada`, ou o domínio correspondente não rodou.
3. **Não aplicável — superfície ausente: <qual>** — todas as categorias que alimentam a linha
   estão `sem_superficie`. Ausência de log de segurança **não** é superfície ausente: é o que a
   linha de AU avalia.
4. **Sem desvio no escopo analisado** — nos demais casos.

Nunca use "Conforme", "Parcial" nem "Não conforme".

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
| <título do candidato> | <caminho:linha> | <caçador de origem> | <padrão FP-NN citado, "evidência não reproduzível", ou a conclusão dos passos 1 a 3> |

## Apêndice B — O que a varredura não cobriu

- **Cobertura por domínio:** <para cada caçador, as categorias com status `nao_verificada` ou
  `sem_superficie` e o motivo; e os arquivos da superfície que ficaram sem leitura.>
- **Domínios fora de escopo:** <segurança de memória em C/C++ quando o inventário detectar
  código C/C++; práticas SSDF de processo (PO.1, PO.2, PO.4, PS.1, PS.2, PS.3, PW.1, PW.2, PW.6,
  PW.7, PW.8, RV.2, RV.3); limite de tentativas de login (SP 800-63B-4 §3.2.2) e evento de
  segurança não registrado (AU-2), não caçados nesta versão.>
- **Escopo reduzido por decisão:** <critério aplicado no controle de escopo, ou "nenhum — varredura completa".>
- **Diretórios excluídos:** <lista do inventário.>
- **Consulta de vulnerabilidades em dependências:** <fonte, status, quantos pacotes foram
  enviados ao OSV e quantos não foram (e por quê), estado da base NVD local — copiado do
  cabeçalho do caçador, nunca inferido. Consulta pendente não é ausência de vulnerabilidade.>
- **Requisito FIPS:** <declarado pelo argumento `--fips` ou por evidência no repositório, ou
  presumido ausente.>
- **Conteúdo que tentou dirigir a auditoria:** <cada `tentativa_injecao` consolidada: arquivo:linha
  e o resumo recebido, sem copiar o texto original. "Nenhum" quando não houver.>
- **Limites da análise estática:** falhas de lógica de negócio, condição de corrida dependente
  de tempo real, configuração aplicada apenas em runtime, segredo injetado por orquestrador,
  segredo no histórico do git e comportamento de biblioteca de terceiro sem código-fonte
  disponível não são detectáveis por leitura de código.
- **Exige teste dinâmico:** <o que só um teste em execução comprova neste projeto.>
- **Exige revisão manual:** <o que exige conhecimento de negócio que a auditoria não tem.>
````

---

## Gabarito de achado

Todo achado contém os **catorze campos abaixo, nesta ordem**. Nenhum campo é omitido, com uma
única exceção: **Estado** é omitido na primeira execução, quando não há relatório anterior
comparável.

`````markdown
### <Título — a falha em uma linha>

- **Severidade:** Crítica | Alta | Média | Baixa
- **Estado:** novo | persistente (há N execuções)
- **Controle NIST:** <prática SSDF e controle SP 800-53 da tabela canônica; um por linha quando houver mais de um>
- **CWE / OWASP:** CWE-NNN; OWASP ANN:2025 – <categoria>
- **Veredito:** Confirmado | Provável

**O que é:** <a falha em linguagem clara, sem jargão desnecessário>

**Onde está:** `<caminho/arquivo.ext:linha>`. <Todas as ocorrências duplicadas do mesmo padrão,
uma a uma, com caminho e linha. Nunca resuma como "e outras ocorrências".>

**Código atual:**

```<linguagem>
<o trecho vulnerável, copiado do arquivo em disco>
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
<o código já reescrito, pronto para substituir o trecho vulnerável>
```

**Como validar:** <o teste que comprova que a correção fechou a falha — entrada concreta,
resultado esperado, e o teste automatizado a adicionar>
`````

### Regras de preenchimento

1. **Segredo nunca tem valor impresso.** A máscara é o tipo do segredo, o prefixo público do
   provedor quando existir (`AKIA`, `ghp_`, `sk_live_`) e o comprimento — por exemplo
   `AKIA…(20 caracteres)`. Senha, token sem prefixo conhecido e formato desconhecido não mostram
   nenhum caractere: `<valor com 30 caracteres>`. O campo *Código atual* traz a linha com o valor
   já substituído pela máscara, e *Como corrigir* abre com a instrução de **rotacionar
   imediatamente**, antes de qualquer mudança de código.
2. **Código atual vem do arquivo em disco**, não da transcrição recebida: leia `arquivo:linha` e
   copie as linhas, mascarando segredo. A cerca de código usa mais crases que a maior sequência
   de crases dentro do trecho, para que um trecho com três crases não abra seções falsas no
   relatório.
3. **Achado sem fluxo de dado** (configuração, constante, ausência de controle): o *Caminho de
   exploração* descreve como um atacante alcança o efeito — quem acessa a imagem, o endpoint ou
   o token — em vez de fonte e sink de dado.
4. **Achado de dependência:** a linha *CWE / OWASP* traz também os IDs
   (`CVE-AAAA-NNNN (CVSS x.x, versão, vetor, fonte); GHSA-...`) e, quando houver, `KEV desde
   AAAA-MM-DD`. *Onde está* traz `pacote@versão_instalada`, a cadeia até o pacote direto e as
   versões corrigidas (`→ corrigido em X`). *Código corrigido* é a linha do manifesto com a nova
   versão, ou o override do gerenciador para a transitiva.
5. **Código corrigido é código, não descrição.** Escreva o trecho pronto para substituir o
   vulnerável, na mesma linguagem e no mesmo estilo do arquivo de origem. Ele não foi executado:
   quem aplica revisa e testa.
6. **Ocorrências duplicadas são enumeradas**, todas, no campo *Onde está*.
7. **Um achado por falha**, não por arquivo. O mesmo padrão em cinco arquivos é um achado com
   cinco ocorrências, desde que a correção seja a mesma.

---

## JSON ao lado do relatório

Mesmo nome do relatório, extensão `.json`. É o que a próxima execução usa para comparar.

```json
{
  "versao_plugin": "<versão>",
  "data": "YYYY-MM-DD",
  "escopo": {"tipo": "completo | subdiretorio | diff", "subdiretorio": null, "base": null, "arquivos": null},
  "contagem": {"critica": 0, "alta": 0, "media": 0, "baixa": 0, "total": 0},
  "achados": [
    {
      "chave": "<arquivo>|<categoria>|<primeiros 60 caracteres do trecho, sem espaços repetidos e com segredo mascarado>",
      "id": "<id>", "titulo": "<título>", "categoria": "<INJ·1, AUTH·2, ...>", "cwe": "CWE-NNN",
      "severidade": "Crítica | Alta | Média | Baixa", "veredito": "Confirmado | Provável",
      "arquivo": "<caminho>", "linha": 0, "estado": "novo | persistente",
      "execucoes": 1, "pacote": null, "ids_vulnerabilidade": []
    }
  ],
  "descartados": [{"chave": "<mesma forma>", "titulo": "<título>", "motivo": "<motivo>"}],
  "painel": [{"linha": "<publicação / função>", "estado": "<estado>"}]
}
```
