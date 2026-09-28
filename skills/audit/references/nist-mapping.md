# Mapeamento NIST — norma de referência da auditoria

SP 800-218 (SSDF) é a espinha dorsal desta auditoria. As demais publicações entram como apoio
por domínio. **Todo achado cita o controle NIST violado e correlaciona com CWE e com a
categoria do OWASP Top 10:2025, sempre a partir da [tabela canônica](#tabela-canônica) desta
página** — nunca de memória.

A auditoria lê código. Ela aponta desvios encontrados no escopo analisado; **não certifica
conformidade** com nenhuma publicação, porque boa parte dos controles é de processo e de
operação.

## Publicações e revisões vigentes

| Publicação | Revisão usada | Escopo na auditoria |
| :--- | :--- | :--- |
| SP 800-218 (SSDF) | v1.1, fev/2022 (a v1.2, SP 800-218 Rev. 1, é rascunho de dez/2025) | Espinha dorsal: práticas verificáveis no código e na configuração |
| SP 800-53 | Rev. 5, release 5.2.0 (ago/2025) | Controles citados em cada achado |
| CSF | 2.0 | Categorias e subcategorias do painel |
| SP 800-63B | **Rev. 4, final em jul/2025** (substitui a Rev. 3) | Senha, armazenamento de credencial, sessão, MFA, cookie e CSRF |
| FIPS 140-3 / SP 800-131A | SP 800-131A Rev. 2 (a Rev. 3 é rascunho de out/2024) | Algoritmos aprovados, proibidos e tamanhos de chave |
| SP 800-190 | 2017 | Container: imagem, usuário, segredo, superfície |
| SP 800-92 | 2006 (a Rev. 1 é rascunho de out/2023) | Log: o que nunca registrar e integridade do arquivo de log. Para citação, prefira AU-2 e AU-9 |
| OWASP Top 10 | **2025** | Categoria de cada achado |

## Práticas SSDF

| Prática | Título curto | Na auditoria |
| :--- | :--- | :--- |
| PO.3 | Implementar ferramentas de apoio | Pipeline de CI/CD (CONF·13) |
| PO.5 | Manter ambientes de desenvolvimento seguros | Pipeline de CI/CD (CONF·13) |
| PW.4 | Reutilizar software existente e seguro | Dependências, imagem base, fontes de pacote |
| PW.5 | Criar código-fonte seguro | Injeção, autenticação, criptografia, tratamento de erro |
| PW.9 | Configurar o software com padrão seguro | Container, debug, headers, CORS, permissões, IaC |
| RV.1 | Identificar e confirmar vulnerabilidades continuamente | Vulnerabilidade conhecida e pacote malicioso em dependência |
| PO.1, PO.2, PO.4, PS.1, PS.2, PS.3, PW.1, PW.2, PW.6, PW.7, PW.8, RV.2, RV.3 | Práticas de processo, de proteção do repositório e de build | **Não avaliadas** por leitura de código: vão ao Apêndice B |

## Controles SP 800-53 Rev. 5 citados

| Controle | Título | Controle | Título |
| :--- | :--- | :--- | :--- |
| AC-3 | Access Enforcement | IA-2 | Identification and Authentication (Organizational Users) |
| AC-4 | Information Flow Enforcement | IA-2(1), IA-2(2) | Multi-factor Authentication |
| AC-6 | Least Privilege | IA-5 | Authenticator Management |
| AC-12 | Session Termination | IA-5(7) | No Embedded Unencrypted Static Authenticators |
| AU-2 | Event Logging | RA-5 | Vulnerability Monitoring and Scanning |
| AU-9 | Protection of Audit Information | SA-22 | Unsupported System Components |
| CM-2 | Baseline Configuration | SC-7 | Boundary Protection |
| CM-6 | Configuration Settings | SC-8 | Transmission Confidentiality and Integrity |
| CM-7 | Least Functionality | SC-12 | Cryptographic Key Establishment and Management |
| SI-2 | Flaw Remediation | SC-13 | Cryptographic Protection |
| SI-3 | Malicious Code Protection | SC-23 | Session Authenticity |
| SI-7 | Software, Firmware, and Information Integrity | SR-3 | Supply Chain Controls and Processes |
| SI-10 | Information Input Validation | SR-4 | Provenance |
| SI-11 | Error Handling | SR-11 | Component Authenticity |
| SI-15 | Information Output Filtering | | |

## Subcategorias CSF 2.0 citadas

| Subcategoria | Texto resumido |
| :--- | :--- |
| PR.AA-01 | Identidades e credenciais são gerenciadas |
| PR.AA-03 | Usuários, serviços e hardware são autenticados |
| PR.AA-05 | Permissões são definidas, aplicadas e revistas, com menor privilégio |
| PR.DS-01 | Dado em repouso é protegido |
| PR.DS-02 | Dado em trânsito é protegido |
| PR.PS-01 | Práticas de gestão de configuração são aplicadas |
| PR.PS-02 | Software é mantido, substituído e removido conforme o risco |
| PR.PS-04 | Registros de log são gerados e disponibilizados para monitoramento |
| PR.PS-06 | Práticas de desenvolvimento seguro estão integradas ao ciclo de vida |
| PR.IR-01 | Redes e ambientes são protegidos de acesso lógico não autorizado |
| ID.RA-01 | Vulnerabilidades nos ativos são identificadas, validadas e registradas |
| GV.SC-07 | Riscos de fornecedor, de seus produtos e de terceiros são entendidos e monitorados |
| DE.CM-09 | Hardware, software e ambientes de execução são monitorados (operação: **não avaliado**) |

## OWASP Top 10:2025

| 2025 | Categoria | Equivalente em 2021 |
| :--- | :--- | :--- |
| A01 | Broken Access Control | A01, mais A10 (SSRF) |
| A02 | Security Misconfiguration | A05 |
| A03 | Software Supply Chain Failures | A06, ampliada |
| A04 | Cryptographic Failures | A02 |
| A05 | Injection | A03 |
| A06 | Insecure Design | A04 |
| A07 | Authentication Failures | A07 |
| A08 | Software or Data Integrity Failures | A08 |
| A09 | Security Logging and Alerting Failures | A09 |
| A10 | Mishandling of Exceptional Conditions | nova |

## Tabela canônica

Uma linha por categoria de caçador. `CWE`, `OWASP`, `SSDF`, `SP 800-53` e `CSF 2.0` são os
valores que o caçador copia para o candidato. As linhas do painel de conformidade que cada
categoria alimenta saem das colunas: a prática SSDF alimenta a linha da prática; o controle SP
800-53, a linha da família; a subcategoria CSF, a linha da categoria; e a coluna `Outras`, a
linha da publicação.

### cacador-injecao

| Id | Categoria | CWE | OWASP 2025 | SSDF | SP 800-53 | CSF 2.0 | Outras |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| INJ·1 | SQL injection | CWE-89 | A05 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·2 | NoSQL injection | CWE-943 | A05 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·3 | Command injection | CWE-78 | A05 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·4 | Path traversal | CWE-22 | A01 | PW.5 | SI-10, AC-3 | PR.PS-06 | — |
| INJ·5 | SSTI | CWE-1336 | A05 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·6 | XSS refletido | CWE-79 | A05 | PW.5 | SI-10, SI-15 | PR.PS-06 | — |
| INJ·7 | XSS armazenado | CWE-79 | A05 | PW.5 | SI-10, SI-15 | PR.PS-06 | — |
| INJ·8 | XSS baseado em DOM | CWE-79 | A05 | PW.5 | SI-10, SI-15 | PR.PS-06 | — |
| INJ·9 | Desserialização insegura | CWE-502 | A08 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·10 | XXE | CWE-611 | A02 | PW.5 | SI-10, CM-6 | PR.PS-06 | — |
| INJ·11 | SSRF | CWE-918 | A01 | PW.5 | SI-10, SC-7 | PR.PS-06, PR.IR-01 | — |
| INJ·12 | Open redirect | CWE-601 | A01 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·13 | LDAP injection | CWE-90 | A05 | PW.5 | SI-10 | PR.PS-06 | — |
| INJ·14 | Header/CRLF injection, e injeção em linha de log | CWE-113; CWE-117 em log | A05 | PW.5 | SI-10; AU-9 em log | PR.PS-06; PR.PS-04 em log | SP 800-92 em log |
| INJ·15 | Injeção de código no servidor | CWE-95; CWE-917 em expression language | A05 | PW.5 | SI-10 | PR.PS-06 | — |

### cacador-login-permissao

| Id | Categoria | CWE | OWASP 2025 | SSDF | SP 800-53 | CSF 2.0 | Outras |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| AUTH·1 | Rota sensível sem autenticação | CWE-306 | A07 | PW.5 | IA-2, AC-3 | PR.AA-03 | — |
| AUTH·2 | Autorização quebrada / IDOR | CWE-639 | A01 | PW.5 | AC-3 | PR.AA-05 | — |
| AUTH·3 | Escalonamento de privilégio, horizontal ou vertical | CWE-269 | A01 | PW.5 | AC-6, AC-3 | PR.AA-05 | — |
| AUTH·4 | Armazenamento de senha inadequado | CWE-916; CWE-256 em texto claro | A04 | PW.5 | IA-5 | PR.AA-01 | SP 800-63B; FIPS quando exigido |
| AUTH·5 | Política de senha abaixo do SP 800-63B-4 | CWE-521 | A07 | PW.5 | IA-5 | PR.AA-01 | SP 800-63B |
| AUTH·6 | Sessão sem expiração ou sem invalidação | CWE-613 | A07 | PW.5 | AC-12, SC-23 | PR.AA-03 | SP 800-63B |
| AUTH·7 | JWT sem verificação, `alg: none` ou claims não verificados | CWE-347 | A07 | PW.5 | IA-2, SC-23 | PR.AA-03 | — |
| AUTH·8 | Segredo de assinatura fraco | CWE-1391 | A07 | PW.5 | IA-5, SC-12 | PR.AA-01 | — |
| AUTH·9 | MFA ausente onde exigido | CWE-308 | A07 | PW.5 | IA-2(1), IA-2(2) | PR.AA-03 | SP 800-63B |
| AUTH·10 | Cookie de sessão sem `Secure`, `HttpOnly` ou `SameSite` | CWE-614; CWE-1004; CWE-1275 | A07 | PW.5 | SC-8, SC-23 | PR.DS-02 | SP 800-63B |
| AUTH·11 | CSRF | CWE-352 | A01 | PW.5 | SC-23 | PR.AA-03 | SP 800-63B |
| AUTH·12 | Fixação de sessão | CWE-384 | A07 | PW.5 | SC-23 | PR.AA-03 | SP 800-63B |

### cacador-cripto-segredos

| Id | Categoria | CWE | OWASP 2025 | SSDF | SP 800-53 | CSF 2.0 | Outras |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| CRYPTO·1 | Algoritmo proibido | CWE-327 | A04 | PW.5 | SC-13 | PR.DS-01 | FIPS |
| CRYPTO·2 | Tamanho de chave insuficiente | CWE-326 | A04 | PW.5 | SC-12, SC-13 | PR.DS-01 | FIPS |
| CRYPTO·3 | Modo ECB | CWE-327 | A04 | PW.5 | SC-13 | PR.DS-01 | FIPS |
| CRYPTO·4 | IV ou nonce estático ou reutilizado | CWE-329; CWE-323 | A04 | PW.5 | SC-12, SC-13 | PR.DS-01 | FIPS |
| CRYPTO·5 | PRNG não criptográfico para valor sensível | CWE-338 | A04 | PW.5 | SC-13 | PR.DS-01 | FIPS |
| CRYPTO·6 | Salt ausente ou fixo | CWE-759; CWE-760 | A04 | PW.5 | IA-5, SC-13 | PR.DS-01 | SP 800-63B |
| CRYPTO·7 | Segredo hardcoded no código ou na configuração | CWE-798 | A07 | PW.5 | IA-5(7) | PR.AA-01 | — |
| CRYPTO·8 | Verificação de certificado desabilitada | CWE-295 | A04 | PW.5 | SC-8 | PR.DS-02 | — |
| CRYPTO·9 | TLS abaixo de 1.2 | CWE-326 | A04 | PW.5 | SC-8, SC-13 | PR.DS-02 | FIPS |
| CRYPTO·10 | Comparação de segredo não constante no tempo | CWE-208 | A04 | PW.5 | SC-13 | PR.DS-01 | — |
| CRYPTO·11 | Segredo ou dado sensível gravado em log | CWE-532 | A09 | PW.5 | AU-9 | PR.PS-04 | SP 800-92 |

### cacador-config-infra

| Id | Categoria | CWE | OWASP 2025 | SSDF | SP 800-53 | CSF 2.0 | Outras |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| CONF·1 | Container rodando como root | CWE-250 | A02 | PW.9 | AC-6, CM-6 | PR.PS-01 | SP 800-190 |
| CONF·2 | Imagem base sem pin | CWE-1357 | A03 | PW.4 | CM-2, SI-7 | PR.PS-02 | SP 800-190 |
| CONF·3 | Segredo em imagem, IaC ou definição de serviço | CWE-798 | A02 | PW.9 | IA-5(7) | PR.AA-01 | SP 800-190 |
| CONF·4 | Depurador ou console ativo e alcançável | CWE-489 | A02 | PW.9 | CM-7, SC-7 | PR.PS-01 | SP 800-190 |
| CONF·5 | CORS permissivo | CWE-942 | A02 | PW.9 | AC-4 | PR.PS-01 | — |
| CONF·6 | Headers de segurança ausentes | CWE-693; CWE-1021 | A02 | PW.9 | CM-6 | PR.PS-01 | — |
| CONF·7 | Permissão excessiva de arquivo, diretório, volume ou arquivo de log | CWE-732 | A02 | PW.9 | AC-6; AU-9 em log | PR.PS-01; PR.PS-04 em log | SP 800-92 em log |
| CONF·8 | Modo debug em produção | CWE-489 | A02 | PW.9 | CM-6, CM-7 | PR.PS-01 | — |
| CONF·9 | Mensagem de erro com stack trace | CWE-209 | A10 | PW.5 | SI-11 | PR.PS-01 | — |
| CONF·10 | Endpoint administrativo sem proteção de rede | CWE-306 | A01 | PW.9 | AC-3, SC-7 | PR.IR-01 | — |
| CONF·11 | Storage ou bucket com acesso público | CWE-732 | A01 | PW.9 | AC-3, AC-6 | PR.DS-01 | — |
| CONF·12 | IaC com privilégio excessivo ou security group aberto | CWE-250; CWE-284 | A02 | PW.9 | AC-6, SC-7 | PR.AA-05, PR.IR-01 | SP 800-190 em cluster |
| CONF·13 | Pipeline de CI/CD inseguro | CWE-829; CWE-78 em injeção de script | A03 | PO.3, PO.5 | SR-3, CM-6, AC-6 | PR.PS-06 | — |

### cacador-dependencias

| Id | Categoria | CWE | OWASP 2025 | SSDF | SP 800-53 | CSF 2.0 | Outras |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| DEP·1 | Vulnerabilidade conhecida em dependência direta | CWE-1395 | A03 | RV.1, PW.4 | RA-5, SI-2 | ID.RA-01 | — |
| DEP·2 | Versão sem pin | CWE-494 | A03 | PW.4 | CM-2, SR-4 | PR.PS-02 | — |
| DEP·3 | Dependência abandonada ou sem manutenção | CWE-1104 | A03 | PW.4 | SA-22 | PR.PS-02 | — |
| DEP·4 | Fonte fora do registro público | CWE-494 | A03 | PW.4 | SR-4, SR-11 | GV.SC-07 | — |
| DEP·5 | Ausência de lockfile | CWE-494 | A03 | PW.4 | CM-2, SR-4 | PR.PS-02 | — |
| DEP·6 | Vulnerabilidade conhecida em dependência transitiva | CWE-1395 | A03 | RV.1, PW.4 | RA-5, SI-2 | ID.RA-01 | — |
| DEP·7 | Licença incompatível | sem CWE aplicável | A03 | PW.4 | SR-3 | GV.SC-07 | — |
| DEP·8 | Pacote malicioso conhecido | CWE-506 | A03 | PW.4, RV.1 | SR-11, SI-3 | GV.SC-07 | — |

## Regras SP 800-63B-4 aplicáveis a código

Cite como "SP 800-63B-4 §seção". "Fator único" é qualquer conta que entra só com senha — MFA
opcional não baixa o mínimo para 8.

| Regra | Força | Verificação | Vira achado quando |
| :--- | :--- | :--- | :--- |
| Comprimento mínimo (§3.1.1.2) | SHALL | Validador de cadastro e de troca | Menos de 15 caracteres quando a senha é o único fator; menos de 8 quando ela só é usada junto com outro fator |
| Comprimento máximo (§3.1.1.2) | SHOULD | Validador e coluna do banco | Aceita menos de 64 caracteres |
| Regra de composição (§3.1.1.2) | SHALL NOT | Validação | Exige maiúscula, número, símbolo ou qualquer mistura de tipos |
| Troca periódica (§3.1.1.2) | SHALL NOT | Política de expiração | Expira senha por tempo, sem indício de comprometimento |
| Lista de senhas comprometidas (§3.1.1.2) | SHALL | Cadastro e troca | Nenhuma checagem contra lista de senhas comuns, esperadas ou vazadas |
| Dica e pergunta secreta (§3.1.1.2, §4.2) | SHALL NOT | Cadastro e recuperação | Guarda dica de senha, ou usa pergunta secreta ao escolher senha ou para recuperar a conta |
| Senha inteira (§3.1.1.2) | SHALL | Hash e comparação | Trunca a senha — bcrypt corta em 72 bytes sem pré-hash |
| Gerenciador de senha e colar (§3.1.1.2) | SHALL / SHOULD | Front-end | Bloqueia autofill (SHALL) ou colar (SHOULD) no campo de senha |
| Armazenamento (§3.1.1.2) | SHALL | Função de hash | Sem salt, salt abaixo de 32 bits, ou hash sem esquema de senha — ver criptografia |
| Limite de tentativas (§3.2.2) | SHALL | Fluxo de login | No máximo 100 falhas seguidas por conta. **Nesta versão não é categoria**: o limitador costuma ficar no gateway ou no IdP, então a ausência no código vai para a cobertura como não verificada |
| Timeout de sessão (§2.1.3, §2.2.3, §2.3.3) | SHALL / SHOULD | Emissão e renovação de sessão | Sem timeout absoluto (SHALL em todo AAL). Limites numéricos — AAL1 até 30 dias; AAL2 até 24 h e inatividade até 1 h; AAL3 até 12 h e inatividade até 15 min — só quando o AAL alvo estiver declarado no projeto |
| Cookie de sessão (§5.1.1) | SHALL / SHOULD | Emissão do cookie | Sem `Secure` (SHALL); sem `HttpOnly` ou `SameSite` (SHOULD) |
| CSRF (§5.1) | SHALL | Requisições que mudam estado | Sessão por cookie sem token anti-CSRF verificado nem checagem de origem |
| MFA | — | Conta privilegiada | Segundo fator ausente em conta administrativa ou onde o próprio projeto exige |
| Notificação após recuperação (§4.2) | SHALL | Recuperação de conta | Recupera a conta sem avisar o titular |

## Criptografia

**Requisito FIPS.** A aprovação FIPS só vira achado quando o projeto exige FIPS: argumento
`--fips` da auditoria, modo FIPS configurado, ou FedRAMP ou contrato citado no repositório. Sem
isso, os algoritmos da seção "aceitáveis fora de FIPS" não são achado, e o relatório registra no
Apêndice B que o requisito FIPS foi presumido ausente. **Nunca recomende trocar Argon2id por
PBKDF2 fora de escopo FIPS.** Os algoritmos proibidos são achado com ou sem FIPS: são fracos.

### Proibidos (SP 800-131A Rev. 2)

| Item | Onde costuma aparecer | O que faz virar achado |
| :--- | :--- | :--- |
| MD5 | Hash de senha, assinatura, verificação de integridade | Qualquer uso em contexto de segurança. Checksum, chave de cache ou deduplicação não é achado — ver FP-01 e FP-11 |
| SHA-1 | Assinatura digital, certificado | Assinatura ou certificado. HMAC-SHA-1 e SHA-1 como PRF do PBKDF2 ainda são aceitos pelo SP 800-132: não são achado, mas não devem entrar em sistema novo |
| DES | Cifra de dado em repouso, integração legada | Qualquer uso |
| 3DES / TDEA | Cifra legada, integração financeira antiga | Cifrar com 3DES é proibido desde 2024; só decifrar dado legado é permitido |
| RC4 | TLS antigo, ofuscação caseira | Qualquer uso |
| ECB | `AES/ECB/PKCS5Padding`, `aes-256-ecb`, `MODE_ECB`, `Cipher.getInstance("AES")` | Qualquer uso sobre dado com estrutura |
| RSA abaixo de 2048 bits | Par de chaves, certificado, assinatura de JWT | Chave gerada ou aceita abaixo de 2048 bits |
| Chave simétrica abaixo de 128 bits | Geração ou derivação de chave | Força efetiva abaixo de 128 bits |

### Aprovados pelo FIPS 140-3 (SP 800-131A Rev. 2)

| Item | Uso correto | O que faz virar achado mesmo sendo aprovado |
| :--- | :--- | :--- |
| AES-128/192/256 em GCM | Cifra autenticada | Nonce estático ou reutilizado com a mesma chave, ou tag não verificada |
| AES em CBC com HMAC | Cifra e autenticação separadas | IV estático ou previsível, HMAC ausente, ou HMAC verificado depois de decifrar |
| SHA-256 / SHA-384 / SHA-512 / SHA-3 | Integridade, assinatura, HMAC | Uso direto como hash de senha, sem esquema de senha e sem salt |
| RSA com 2048 bits ou mais | Assinatura e troca de chave | Padding PKCS#1 v1.5 para cifra, chave privada em arquivo versionado, assinatura aceita sem verificação. RSA-2048 dá 112 bits de força, aceitos até 2030: para dado de vida longa, prefira 3072 |
| ECDSA / EdDSA em P-256, P-384, P-521, Ed25519 | Assinatura | Curva fora do conjunto, nonce reutilizado em ECDSA, verificação desligada |
| PBKDF2 (SP 800-132) | Hash de senha e derivação de chave | Salt ausente, fixo ou compartilhado; salt abaixo de 32 bits (SP 800-63B-4); iterações abaixo de 1.000 (mínimo do SP 800-132). Referência prática: OWASP recomenda 600.000 iterações com HMAC-SHA-256 |

### Aceitáveis fora de escopo FIPS

| Item | Uso correto | O que faz virar achado |
| :--- | :--- | :--- |
| Argon2id | Hash de senha | Parâmetros abaixo de m = 19 MiB, t = 2, p = 1 (referência OWASP) |
| scrypt | Hash de senha | N abaixo de 2^17 com r = 8 e p = 1 (referência OWASP) |
| bcrypt | Hash de senha | Custo abaixo de 10, ou senha acima de 72 bytes truncada em silêncio (SP 800-63B-4 exige verificar a senha inteira) |
| ChaCha20-Poly1305 | Cifra autenticada | Nonce reutilizado com a mesma chave |

### Defaults inseguros por linguagem

| Linguagem | Construção | Problema |
| :--- | :--- | :--- |
| Java | `Cipher.getInstance("AES")` ou `("DES")` sem modo | O provedor padrão usa ECB com PKCS5Padding |
| Java | `new Random()`, `Math.random()` | Não criptográfico; use `SecureRandom` |
| Node.js | `crypto.createCipher`, `crypto.createDecipher` | Deriva a chave com MD5, sem salt e sem IV; removido no Node 22 |
| Node.js | `Math.random()` | Não criptográfico; use `crypto.randomBytes` ou `crypto.randomUUID` |
| Python | módulo `random` | Não criptográfico; use `secrets` |
| Python | `ssl._create_unverified_context()`, `verify=False` | Verificação de certificado desligada |
| PHP | `rand()`, `mt_rand()`, `uniqid()` | Não criptográfico; use `random_bytes` |
| .NET | `System.Random`; `CipherMode.ECB` | Não criptográfico; ECB |
| Go | `math/rand` | Não criptográfico; use `crypto/rand` |
| Go | `InsecureSkipVerify: true` | Verificação de certificado desligada |

### Regras transversais

| Regra | O que faz virar achado |
| :--- | :--- |
| Origem de aleatoriedade | Gerador não criptográfico para token, chave, nonce, IV, senha temporária, identificador de sessão ou código de recuperação |
| Salt | Ausente, fixo no código, igual para todos os usuários, ou abaixo de 32 bits |
| IV e nonce | Constante no código, derivado de valor previsível, ou reutilizado com a mesma chave |
| Comparação de segredo | Token, HMAC, hash de senha ou assinatura comparados com igualdade comum, em vez de comparação de tempo constante |
| Verificação de certificado | Cadeia ou hostname não verificados (`rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`, gerenciador de confiança que aceita tudo) |
| Versão de TLS | TLS 1.0, TLS 1.1, SSLv2 ou SSLv3 como versão mínima |

Prontidão pós-quântica (NIST IR 8547, rascunho) não é achado nesta versão.

## Vulnerabilidade em dependência

O orquestrador roda `sca_scan.py` uma vez, antes dos caçadores. O script lê os lockfiles,
consulta o **OSV** (api.osv.dev) por nome e versão exata — com as faixas nativas do GitHub
Advisory Database, PyPA, Go, RustSec e outras fontes — e completa cada CVE com a nota, o CWE e a
data de entrada no catálogo KEV da CISA a partir da base local da NVD, quando ela existe. O
`cacador-dependencias` lê o JSON e decide a alcançabilidade.

Por que não só a NVD: desde abril de 2026 a NVD enriquece com CPE e nota própria apenas os CVEs
do KEV, de software usado pelo governo federal americano e de "critical software" (EO 14028).
A maioria dos CVEs novos fica sem CPE, e uma consulta que dependa só dele não os encontra. O
SSDF RV.1.1 pede reunir informação de vulnerabilidade de fontes públicas; a NVD continua como
fonte do metadado de cada CVE.

Privacidade: no modo online, nome e versão de cada pacote público vão para api.osv.dev. Pacote
npm resolvido fora do registro público não é enviado; com o argumento `--offline`, nada sai da
máquina e só o inventário é produzido. O que foi e o que não foi enviado vai ao Apêndice B.

Todo achado de vulnerabilidade em dependência se correlaciona a **SP 800-218 RV.1**.
