# Guia de falso positivo

`validador-falsos-positivos` consulta este catálogo **antes** de validar. Candidato que casa com um
padrão abaixo **e não atende** à condição descrita em "o que faria disso uma falha real" é
descartado direto, sem rastreamento completo do fluxo, citando o padrão como motivo do
descarte. Candidato que casa com o padrão **mas atende** à condição segue para o rastreamento
completo dos quatro passos.

Cada descarte vai para o Apêndice A do relatório, com o número e o nome do padrão.

---

## FP-01 — Hash não criptográfico para checksum, chave de cache ou deduplicação

**Exemplo que dispara o alarme:**

```python
cache_key = hashlib.md5(f"{user_id}:{query}".encode()).hexdigest()
```

**Por que geralmente não é falha:** MD5 e CRC aqui servem para distribuir e comparar valores,
não para resistir a adversário. A colisão custaria ao atacante, no máximo, um cache errado; não
há decisão de segurança apoiada no hash.

**O que faria disso uma falha real:** o hash decidir autenticidade, integridade contra
adversário ou identidade — hash de senha, verificação de assinatura, comparação de token,
validação de integridade de artefato baixado, ou chave de cache usada como chave de
autorização.

---

## FP-02 — `Math.random()` em contexto não sensível

**Exemplo que dispara o alarme:**

```javascript
const jitter = Math.random() * 500;
setTimeout(retry, backoff + jitter);
```

**Por que geralmente não é falha:** o valor não protege nada. Previsibilidade do jitter, de uma
cor de UI ou de um identificador de teste não dá vantagem a um atacante.

**O que faria disso uma falha real:** o valor virar token de sessão, código de recuperação de
senha, senha temporária, nonce, IV, chave, identificador de convite, ou qualquer valor cuja
adivinhação conceda acesso.

---

## FP-03 — Credencial em `.env.example`, `.env.sample`, fixture de teste ou documentação

**Exemplo que dispara o alarme:**

```
# .env.example
DATABASE_URL=postgres://user:changeme@localhost:5432/appdb
API_KEY=your-api-key-here
```

**Por que geralmente não é falha:** o arquivo existe para documentar as variáveis exigidas. O
valor é placeholder, não credencial.

**O que faria disso uma falha real:** o valor ser um segredo real — formato de chave real
(prefixo de provedor, comprimento e entropia compatíveis), host apontando para ambiente real,
ou o mesmo valor aparecendo em código de produção. Nesse caso, aplique a Regra 4 de
[severity-rubric.md](severity-rubric.md) e classifique a origem.

---

## FP-04 — Endpoint público intencional

**Exemplo que dispara o alarme:**

```javascript
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
app.post('/webhooks/stripe', verifyStripeSignature, handleEvent);
```

**Por que geralmente não é falha:** health check, página de login e webhook com verificação de
assinatura própria são públicos por projeto. O webhook tem seu próprio mecanismo de
autenticação, que não é a sessão do aplicativo.

**O que faria disso uma falha real:** o health check devolver configuração, variáveis de
ambiente, versão detalhada de dependência ou estado interno; o webhook não verificar a
assinatura, verificar com comparação não constante no tempo, ou aceitar requisição quando a
verificação falha.

---

## FP-05 — Framework aplica escaping automático no template

**Exemplo que dispara o alarme:**

```jsx
<div className="comment">{userComment}</div>
```

**Por que geralmente não é falha:** a camada de template já escapa a interpolação por padrão —
React em JSX, Jinja2 com autoescape ligado, Razor, Blade, Thymeleaf. A saída não vira HTML
executável.

**O que faria disso uma falha real:** o escaping ser contornado — `dangerouslySetInnerHTML`,
`v-html`, filtro `|safe`, `Html.Raw`, `{!! !!}`, autoescape desligado na configuração do
ambiente de template, ou interpolação dentro de atributo de evento, `href`/`src` com esquema
`javascript:`, bloco `<script>` ou bloco `<style>`, onde o escaping de HTML não protege.

---

## FP-06 — Query parametrizada lida como concatenação por causa de formatação

**Exemplo que dispara o alarme:**

```python
cursor.execute(
    "SELECT id, email FROM users "
    "WHERE tenant_id = %s AND status = %s",
    (tenant_id, status),
)
```

**Por que geralmente não é falha:** a concatenação é de literais de string em tempo de
compilação, para quebrar a linha. Os valores externos chegam como parâmetros ligados pelo
driver.

**O que faria disso uma falha real:** qualquer fragmento da string vir de variável em tempo de
execução — interpolação, `+` com variável, `format()`, f-string, template literal — mesmo que
outros valores sigam parametrizados. Nome de tabela ou de coluna montado a partir de entrada
externa também é falha real, porque não é parametrizável pelo driver.

---

## FP-07 — CVE em dependência cujo caminho vulnerável não é usado

**Exemplo que dispara o alarme:** o pacote `lodash` está no lockfile com um CVE em
`lodash.template`, e o projeto importa apenas `lodash/get`.

**Por que geralmente não é falha:** o código vulnerável não é alcançável a partir do projeto. O
risco declarado pelo scanner não corresponde ao risco real da aplicação.

**O que faria disso uma falha real:** o módulo, função ou opção afetada ser importada direta ou
transitivamente; o CVE estar no caminho de carregamento do pacote e não em um submódulo
isolado; ou a exploração não depender de chamar a função afetada (por exemplo, prototype
pollution disparada no parsing de entrada). Na impossibilidade de determinar a alcançabilidade,
o veredito é **provável**, não descartado.

---

## FP-08 — SQL montado com constante literal, sem entrada externa

**Exemplo que dispara o alarme:**

```go
const activeUsersQuery = "SELECT id FROM users WHERE status = '" + StatusActive + "'"
```

**Por que geralmente não é falha:** `StatusActive` é constante do próprio código. Não há
fronteira de confiança atravessada; nenhum dado externo entra na instrução.

**O que faria disso uma falha real:** a constante deixar de ser constante — vir de arquivo de
configuração editável, de variável de ambiente controlada por terceiro, de banco de dados
alimentado por usuário, ou de argumento de função que recebe entrada externa em qualquer
chamada.

---

## FP-09 — `eval` ou reflexão sobre entrada controlada e constante

**Exemplo que dispara o alarme:**

```python
handler = getattr(handlers_module, HANDLER_NAMES[event_type])
```

**Por que geralmente não é falha:** o nome resolvido vem de um mapa fechado definido no código.
A entrada externa escolhe entre opções conhecidas, não fornece o nome.

**O que faria disso uma falha real:** o nome ou a expressão vir de entrada externa, ainda que
filtrada por lista de bloqueio; a lista de opções ser montada dinamicamente a partir de dado
externo; ou a resolução cair em `eval`, `exec`, `new Function`, desserialização ou importação
dinâmica de módulo cujo caminho o usuário influencia.

---

## FP-10 — CORS `*` em API pública sem credenciais e sem dado sensível

**Exemplo que dispara o alarme:**

```javascript
app.use(cors({ origin: '*' }));
```

**Por que geralmente não é falha:** em API que serve conteúdo público, não aceita cookie de
sessão e não devolve dado de usuário, a origem curinga não concede nada que o atacante já não
possa buscar direto.

**O que faria disso uma falha real:** `credentials: true` combinado com origem curinga ou com
reflexo da origem da requisição; a API devolver dado vinculado a usuário autenticado; a
autenticação vir por cookie, por header automático do navegador ou por token em `localStorage`
lido pela página; ou a API estar em rede interna alcançável pelo navegador da vítima.

---

## FP-11 — Algoritmo fraco fora de contexto de segurança

**Exemplo que dispara o alarme:**

```java
String cacheFileName = DigestUtils.sha1Hex(sourceUrl) + ".bin";
```

**Por que geralmente não é falha:** SHA-1 aqui gera um nome de arquivo estável e curto. Não há
adversário a resistir: quem controla a entrada já controla o próprio recurso.

**O que faria disso uma falha real:** o valor passar a decidir segurança — verificação de
integridade de artefato baixado, assinatura, deduplicação usada como controle de acesso,
identificador cuja colisão permita um usuário ler o cache de outro, ou derivação de credencial.
