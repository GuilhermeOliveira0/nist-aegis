# Escala de severidade

A severidade é atribuída **exclusivamente** pelo subagente `avaliador-severidade`. Caçador não
pontua e validador não pontua.

É uma rubrica qualitativa com as **faixas da escala CVSS 3.1**. Ela não calcula um vetor CVSS:
enquadra o achado pelo critério prático da tabela e aplica as regras de desempate. A exceção é o
CVE em dependência, cuja base vem da nota publicada para o CVE.

## Tabela de severidade

| Severidade | Faixa CVSS 3.1 | Critério prático |
| :--- | :--- | :--- |
| Crítica | 9.0–10.0 | Execução remota de código, injeção que expõe todo o banco, segredo de produção exposto, autenticação totalmente contornável, pacote malicioso conhecido |
| Alta | 7.0–8.9 | Injeção limitada, IDOR expondo dado sensível, escalonamento de privilégio, CSRF em ação sensível, criptografia quebrada protegendo dado sensível |
| Média | 4.0–6.9 | Falha explorável sob pré-condição, XSS refletido com interação do usuário, configuração fraca com impacto limitado |
| Baixa | 0.1–3.9 | Impacto marginal, exige acesso já privilegiado, hardening ausente sem exploração direta |

## Base de CVE em dependência

Vale para as categorias 1 e 6 do `cacador-dependencias`.

- A severidade base é a faixa desta tabela que contém a nota CVSS publicada para o CVE: a da
  NVD quando existir, senão a da CNA (inclusive CVSS 4.0), senão o nível do GitHub Advisory
  (`MODERATE` conta como Média). Havendo vários CVEs no achado, vale a maior nota entre os que
  sobreviveram à validação.
- Sem nota nenhuma, enquadre pelo critério prático a partir do impacto descrito; persistindo
  dúvida entre duas faixas, aplique a Regra 5.
- A alcançabilidade não altera a base: `nao_usado` com evidência já foi descartado pelo
  validador (FP-07), e `indeterminado` chega como provável e desce pela Regra 1.
- Dependência só de desenvolvimento, que não entra no artefato de produção, conta como
  `artefato_teste: sim` na Regra 2.
- **CVE no catálogo KEV da CISA nunca termina abaixo de Alta**, qualquer que seja o efeito das
  regras de desempate.
- **Pacote malicioso conhecido (categoria 8) é Crítica fixa**, mesmo só em desenvolvimento: o
  código roda na máquina de quem instala. Não passa pelas regras 1 a 3.
- Registre em `severidade_base` o CVE, a nota, a versão do CVSS, o vetor e a fonte.

Categorias 2, 3, 4, 5 e 7 sem CVE: base Baixa, salvo fonte fora do registro com risco de
dependency confusion demonstrado (Média).

## Regras de desempate — determinísticas, aplicadas nesta ordem

**Regra 1 — Veredito.** Achado **provável** (não confirmado) desce um nível de severidade.
Achado confirmado não sofre ajuste por esta regra.

**Regra 2 — Artefato de teste.** Falha em código de teste, fixture, exemplo ou dependência só de
desenvolvimento desce **dois** níveis, salvo se o artefato for empacotado, publicado ou implantado
em produção. Se o artefato for para produção, esta regra não se aplica.

**Regra 3 — Superfície autenticada.** Desce um nível quando valem as duas condições: (a)
`autenticado: sim`, isto é, a autenticação é exigida antes de alcançar o sink; e (b) o critério
prático que fixou a severidade base descreve um atacante sem conta. **Não se aplica** a IDOR, a
escalonamento de privilégio horizontal ou vertical, a CSRF, a fixação de sessão, nem ao critério
"exige acesso já privilegiado": esses critérios já pressupõem conta ou sessão da vítima, e descer
de novo contaria o mesmo fator duas vezes. Quando o ponto de partida é anônimo
(`autenticado: nao`), escalonamento até papel administrativo — por exemplo, cadastro público que
aceita papel vindo da requisição — enquadra-se na base como "autenticação totalmente contornável"
(Crítica); IDOR em rota sem autenticação mantém a base Alta.

**Regra 4 — Segredo exposto.** Segredo exposto **não passa** pelas regras 1 a 3. Resolve por
origem, em **exatamente duas saídas**:

| Origem do segredo | Severidade |
| :--- | :--- |
| Produção, ou origem indeterminada | **Crítica**, fixa |
| Não produção | **Baixa**, fixa |

"Não produção" exige evidência de que **o valor** não é credencial viva: chave de exemplo
documentada pelo provedor (`AKIAIOSFODNN7EXAMPLE`), prefixo de modo de teste (`sk_test_`,
`pk_test_`, `rk_test_`), ou texto claramente fictício (`changeme`, `your-api-key-here`). O tipo do
arquivo sozinho não decide: valor com formato de credencial real dentro de `.env.example` ou de
fixture é origem indeterminada, logo **Crítica**.

**Regra 5 — Empate residual.** Empate que sobreviva às regras acima resolve para a severidade
**mais alta** entre as candidatas.

**Pré-condições.** `precondicoes` só desce a severidade pelo critério "explorável sob
pré-condição" da linha Média, e só quando a pré-condição não é "ter conta" ou "estar
autenticado" — o login é tratado apenas pela Regra 3. Cada fator desce no máximo uma vez.

## Piso e teto

Nenhum ajuste leva a severidade abaixo de **Baixa** nem acima de **Crítica**. Um achado que
desceria abaixo de Baixa permanece Baixa; um que subiria acima de Crítica permanece Crítica. O
piso de Alta para CVE no KEV prevalece sobre as regras de desempate.

## Formato da justificativa exigida

Para cada achado, `avaliador-severidade` devolve:

- `severidade_base` — a faixa CVSS 3.1 e o critério prático da tabela que a sustenta (ou, para
  CVE em dependência, o CVE, a nota, a versão, o vetor e a fonte).
- `regras_aplicadas` — a lista das regras de desempate acionadas, em ordem, com o efeito de
  cada uma (ex.: `Regra 1: provável, desce de Alta para Média`), e as que foram consideradas e
  **não** se aplicaram por exceção (ex.: `Regra 3: não se aplica a IDOR`).
- `severidade_final` — o resultado após todas as regras.

Se nenhuma regra de desempate se aplicar, registre `regras_aplicadas: nenhuma` e repita a
severidade base como final.

## Exemplos resolvidos

| Achado | Base | Regras | Final |
| :--- | :--- | :--- | :--- |
| SQL injection confirmada em rota pública | Crítica | Nenhuma | Crítica |
| SQL injection provável em rota pública | Crítica | Regra 1 | Alta |
| SQL injection confirmada atrás de login de usuário comum | Crítica | Regra 3 | Alta |
| SQL injection confirmada em helper de fixture de teste não empacotado | Crítica | Regra 2 | Média |
| IDOR confirmado expondo dado de outro usuário, rota com login | Alta | Regra 3 não se aplica a IDOR | Alta |
| Escalonamento vertical confirmado por usuário comum | Alta | Regra 3 não se aplica a escalonamento | Alta |
| Cadastro público aceita `role=admin` da requisição | Crítica | Nenhuma | Crítica |
| ECB com chave fixa protegendo token de sessão, confirmado | Alta | Nenhuma | Alta |
| CVE 7.5 em dependência transitiva, alcançabilidade indeterminada | Alta | Regra 1 | Média |
| CVE 9.8 no KEV em dependência, provável | Crítica | Regra 1, piso de Alta pelo KEV | Alta |
| CVE 6.5 no KEV em dependência só de desenvolvimento | Média | Regra 2 desceria para Baixa; piso de Alta pelo KEV | Alta |
| Pacote malicioso conhecido só em `devDependencies` | Crítica | Fixa | Crítica |
| Chave de API de produção hardcoded | — | Regra 4 | Crítica |
| `AKIAIOSFODNN7EXAMPLE` em documentação | — | Regra 4, exemplo documentado pelo provedor | Baixa |
| Chave com formato real em `.env.example` | — | Regra 4, origem indeterminada | Crítica |
| Header `X-Frame-Options` ausente em painel administrativo autenticado | Baixa | Regra 3 aplicada, piso em Baixa | Baixa |
