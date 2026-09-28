# Escala de severidade

A severidade é atribuída **exclusivamente** pelo subagente `avaliador-severidade`. Caçador não
pontua e validador não pontua.

## Tabela de severidade

| Severidade | Faixa CVSS 3.1 | Critério prático |
| :--- | :--- | :--- |
| Crítica | 9.0–10.0 | Execução remota de código, injeção que expõe todo o banco, segredo de produção exposto, autenticação totalmente contornável |
| Alta | 7.0–8.9 | Injeção limitada, IDOR expondo dado sensível, escalonamento de privilégio, criptografia quebrada protegendo dado sensível |
| Média | 4.0–6.9 | Falha explorável sob pré-condição, XSS refletido com interação do usuário, configuração fraca com impacto limitado |
| Baixa | 0.1–3.9 | Impacto marginal, exige acesso já privilegiado, hardening ausente sem exploração direta |

## Regras de desempate — determinísticas, aplicadas nesta ordem

**Regra 1 — Veredito.** Achado **provável** (não confirmado) desce um nível de severidade.
Achado confirmado não sofre ajuste por esta regra.

**Regra 2 — Artefato de teste.** Falha em código de teste, fixture ou exemplo desce **dois**
níveis, salvo se o artefato for empacotado, publicado ou implantado em produção. Se o artefato
for para produção, esta regra não se aplica.

**Regra 3 — Superfície autenticada.** Caminho autenticado desce um nível em relação ao mesmo
caminho público ou não autenticado. Aplique somente quando a autenticação for exigida antes de
alcançar o sink.

**Regra 4 — Segredo exposto.** Segredo exposto **não passa** pelas regras 1 a 3. Resolve por
origem, em **exatamente duas saídas**:

| Origem do segredo | Severidade |
| :--- | :--- |
| Produção | **Crítica**, fixa |
| Não produção (arquivo de exemplo, fixture, ambiente local documentado como descartável) | **Baixa**, fixa |

Na dúvida sobre a origem, classifique como **produção**.

**Regra 5 — Empate residual.** Empate que sobreviva às regras acima resolve para a severidade
**mais alta** entre as candidatas.

## Piso e teto

Nenhum ajuste leva a severidade abaixo de **Baixa** nem acima de **Crítica**. Um achado que
desceria abaixo de Baixa permanece Baixa; um que subiria acima de Crítica permanece Crítica.

## Formato da justificativa exigida

Para cada achado, `avaliador-severidade` devolve:

- `severidade_base` — a faixa CVSS 3.1 e o critério prático da tabela que a sustenta.
- `regras_aplicadas` — a lista das regras de desempate acionadas, em ordem, com o efeito de
  cada uma (ex.: `Regra 1: provável, desce de Alta para Média`).
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
| Chave de API de produção hardcoded | — | Regra 4 | Crítica |
| Senha em `.env.example` claramente descartável | — | Regra 4 | Baixa |
| Token em arquivo de origem indeterminada | — | Regra 4, dúvida resolve para produção | Crítica |
| Header `X-Frame-Options` ausente em painel administrativo autenticado | Baixa | Regra 3 aplicada, piso em Baixa | Baixa |
