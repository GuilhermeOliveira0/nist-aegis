# Exemplo canônico de achado

Este é o formato de referência. Todo achado do relatório é preenchido com este nível de
detalhe, seguindo o gabarito de catorze campos de
[../references/report-template.md](../references/report-template.md).

---

### SQL injection no endpoint de busca de usuários

- **Severidade:** Crítica
- **Estado:** novo
- **Controle NIST:** SP 800-218 PW.5 (codificação segura); SP 800-53 SI-10 (validação de entrada)
- **CWE / OWASP:** CWE-89; OWASP A03:2021 – Injection
- **Veredito:** Confirmado

**O que é:** O parâmetro de busca `q` é concatenado diretamente numa query SQL sem
parametrização. Um atacante controla parte da instrução executada no banco.

**Onde está:** `src/api/users.js:42`. Ocorrência duplicada do mesmo padrão em
`src/api/orders.js:88`.

**Código atual:**

```javascript
app.get('/api/users/search', (req, res) => {
  const q = req.query.q;
  const sql = `SELECT id, name, email FROM users WHERE name LIKE '%${q}%'`;
  db.query(sql, (err, rows) => res.json(rows));
});
```

**Caminho de exploração:**

1. Fonte: `req.query.q` — entrada externa, não autenticada, rota pública.
2. Sem sanitização, escaping ou parametrização em nenhum ponto.
3. Sink: `db.query` executa a string concatenada.
4. Payload `' UNION SELECT username, password_hash, NULL FROM admin_users --` extrai a tabela de
   administradores.

**Impacto:** Leitura arbitrária do banco, incluindo hashes de senha e dados de outros usuários.
Potencial escrita e `DROP` conforme os privilégios da conexão. Vazamento total de dados.

**Como corrigir:** Substituir a concatenação por query parametrizada com placeholders,
delegando o escaping ao driver.

**Código corrigido:**

```javascript
app.get('/api/users/search', (req, res) => {
  const q = req.query.q;
  const sql = 'SELECT id, name, email FROM users WHERE name LIKE ?';
  db.query(sql, [`%${q}%`], (err, rows) => res.json(rows));
});
```

**Como validar:** Enviar `q=' OR '1'='1` e confirmar que retorna zero linhas — o valor é tratado
como literal, não como lógica. Adicionar teste automatizado que injeta payload de união e
verifica que nenhuma coluna fora do `SELECT` original é retornada.
