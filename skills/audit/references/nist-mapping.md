# Mapeamento NIST — norma de referência da auditoria

SP 800-218 (SSDF) é a espinha dorsal desta auditoria. As demais publicações entram como apoio
por domínio. **Todo achado do relatório cita o controle NIST violado e correlaciona com CWE e
com a categoria correspondente do OWASP Top 10 (2021).**

## Tabela de publicações

| Publicação NIST | Escopo na auditoria | O que verificar em código |
| :--- | :--- | :--- |
| SP 800-218 (SSDF) | Espinha dorsal — práticas PW.4, PW.5, PW.7, PW.8, RV.1 | Práticas de codificação segura, revisão, verificação de vulnerabilidades em dependências |
| SP 800-53 Rev. 5 | Controles de referência para citação | AC (controle de acesso), IA (identificação/autenticação), SC (proteção de sistema/comunicação), SI (integridade), AU (auditoria) |
| CSF 2.0 | Enquadramento de função no painel de conformidade | Mapeia achados para PR.DS, PR.AA, PR.PS, DE.CM |
| SP 800-63B | Autenticação e gestão de sessão | Regras de senha, armazenamento de credencial, ciclo de vida de sessão, MFA |
| FIPS 140-3 / SP 800-131A | Criptografia aprovada e algoritmos legados | Algoritmos permitidos, tamanhos de chave, algoritmos proibidos (ver tabela de criptografia abaixo) |
| SP 800-190 | Segurança de containers | Hardening de imagem, usuário não-root, superfície de ataque, segredos em imagem |
| SP 800-92 | Gestão de logs de segurança | O que logar, o que nunca logar, integridade e retenção de log |

## Práticas SSDF citáveis

| Prática | Título curto | Uso na citação de achado |
| :--- | :--- | :--- |
| PW.4 | Reutilizar software existente seguro | Dependência de terceiro adotada sem verificação de procedência |
| PW.5 | Criar código-fonte seguro | Injeção, validação de entrada ausente, uso inseguro de API criptográfica |
| PW.7 | Revisar e analisar código | Padrão inseguro que revisão ou análise estática deveria ter barrado |
| PW.8 | Testar código executável | Ausência de teste que comprove a mitigação de uma falha de segurança |
| RV.1 | Identificar e confirmar vulnerabilidades continuamente | CVE conhecido em dependência; base de vulnerabilidades desatualizada |

## Controles SP 800-53 Rev. 5 de citação frequente

| Controle | Título curto | Domínio de achado |
| :--- | :--- | :--- |
| AC-3 | Aplicação de acesso | Autorização quebrada, IDOR |
| AC-6 | Menor privilégio | Privilégio excessivo em IaC, container root, conta de banco com permissão ampla |
| IA-2 | Identificação e autenticação de usuário | Rota sensível sem autenticação, MFA ausente |
| IA-5 | Gestão de autenticador | Armazenamento de senha, política de senha, segredo hardcoded |
| SC-8 | Confidencialidade e integridade em trânsito | TLS abaixo de 1.2, verificação de certificado desabilitada |
| SC-12 | Estabelecimento e gestão de chave criptográfica | Chave curta, IV estático, chave privada em código |
| SC-13 | Proteção criptográfica | Algoritmo proibido, modo ECB |
| SI-10 | Validação de entrada de informação | Toda a família de injeção |
| SI-11 | Tratamento de erro | Stack trace vazado ao cliente |
| AU-2 | Eventos de auditoria | Evento de segurança não registrado |
| AU-9 | Proteção da informação de auditoria | Log gravável por processo não privilegiado, log sem controle de integridade |

## Funções CSF 2.0 para o painel de conformidade

| Categoria CSF 2.0 | Leitura no painel | Achados que a rebaixam |
| :--- | :--- | :--- |
| PR.DS (Data Security) | Proteção do dado em repouso e em trânsito | Criptografia fraca, segredo exposto, TLS abaixo de 1.2 |
| PR.AA (Identity Management, Authentication and Access Control) | Identidade e acesso | Autenticação ausente, IDOR, sessão sem expiração |
| PR.PS (Platform Security) | Plataforma e configuração | Container rodando como root, header de segurança ausente, modo debug em produção |
| DE.CM (Continuous Monitoring) | Detecção e monitoramento | Log de segurança ausente, CVE não monitorado em dependência |

## Regras SP 800-63B aplicáveis a código

| Regra | Verificação em código | Vira achado quando |
| :--- | :--- | :--- |
| Comprimento mínimo de senha | Validador do cadastro e da troca de senha | Mínimo abaixo de 8 caracteres |
| Comprimento máximo de senha | Validador e coluna do banco | Máximo abaixo de 64 caracteres |
| Composição obrigatória | Regex de complexidade | Regra de composição imposta como único requisito de força |
| Lista de senhas comprometidas | Fluxo de cadastro e de troca | Nenhuma verificação contra lista de senhas vazadas |
| Rotação periódica arbitrária | Política de expiração de senha | Expiração forçada sem indício de comprometimento |
| Armazenamento de credencial | Função de derivação usada | Hash sem função de derivação aprovada (ver tabela de criptografia) |
| Ciclo de vida de sessão | Emissão, renovação e destruição de sessão | Sessão sem expiração absoluta, sem expiração por inatividade, ou não invalidada no logout |
| MFA | Fluxo de autenticação de conta privilegiada | Segundo fator ausente onde exigido pelo próprio projeto ou em conta administrativa |

## Criptografia — algoritmos proibidos, aprovados e o que vira achado

### Proibidos (FIPS 140-3 / SP 800-131A)

| Item proibido | Onde costuma aparecer | O que faz virar achado |
| :--- | :--- | :--- |
| MD5 | Hash de senha, assinatura, verificação de integridade | Qualquer uso em contexto de segurança. Uso como checksum, chave de cache ou deduplicação não é achado — ver [false-positives.md](false-positives.md) |
| SHA-1 para assinatura | Assinatura digital, certificado, HMAC legado, token de sessão | Uso em assinatura, certificado ou derivação de credencial. Uso como identificador não sensível não é achado |
| DES | Cifra de dado em repouso, integração legada | Qualquer uso. Chave efetiva de 56 bits, quebrável por força bruta |
| 3DES | Cifra legada, protocolo antigo, integração financeira antiga | Qualquer uso, novo ou mantido. Bloco de 64 bits, retirado do conjunto aprovado |
| RC4 | Cifra de fluxo em TLS antigo, ofuscação caseira | Qualquer uso. Viés estatístico no keystream |
| ECB como modo | `AES/ECB/PKCS5Padding`, `aes-256-ecb`, `MODE_ECB` | Qualquer uso sobre dado com estrutura. Blocos de texto claro iguais produzem blocos cifrados iguais |
| RSA com chave abaixo de 2048 bits | Geração de par de chaves, certificado autoassinado, assinatura de JWT | Chave gerada ou aceita abaixo de 2048 bits |
| Chave simétrica abaixo de 128 bits | Parâmetro de geração de chave, chave derivada truncada | Chave de força efetiva abaixo de 128 bits |

### Aprovados

| Item aprovado | Uso correto | O que faz virar achado mesmo sendo aprovado |
| :--- | :--- | :--- |
| AES-128 / AES-192 / AES-256 em GCM | Cifra autenticada de dado sensível | Nonce estático, nonce reutilizado com a mesma chave, ou tag de autenticação não verificada na decifragem |
| AES em CBC com HMAC | Cifra e autenticação separadas | IV estático ou previsível, HMAC ausente, ou HMAC verificado depois de decifrar em vez de encrypt-then-MAC |
| SHA-256 / SHA-384 / SHA-512 | Integridade, assinatura, HMAC | Uso direto como hash de senha, sem função de derivação e sem salt |
| RSA com chave de 2048 bits ou mais | Assinatura digital e troca de chave | Padding PKCS#1 v1.5 para cifra, chave privada em arquivo versionado, ou assinatura aceita sem verificação |
| ECDSA / EdDSA em curvas aprovadas (P-256, P-384, P-521, Ed25519) | Assinatura digital | Curva fora do conjunto aprovado, nonce de assinatura reutilizado em ECDSA, ou verificação de assinatura desabilitada |
| Argon2id | Hash de senha | Parâmetros de memória, iterações ou paralelismo abaixo do recomendado pela biblioteca em uso |
| scrypt | Hash de senha | Parâmetro de custo `N` abaixo do recomendado pela biblioteca em uso |
| bcrypt | Hash de senha | Fator de custo abaixo de 10, ou senha acima de 72 bytes truncada silenciosamente |
| PBKDF2 | Hash de senha e derivação de chave | Contagem de iterações abaixo do recomendado pela biblioteca, salt ausente, salt fixo, ou salt compartilhado entre usuários |

### Regras transversais de criptografia

| Regra | O que faz virar achado |
| :--- | :--- |
| Origem de aleatoriedade | Gerador não criptográfico (`Math.random`, `rand()`, `random.random()`, `mt_rand`) usado para token, chave, nonce, IV, senha temporária, identificador de sessão ou código de recuperação |
| Salt | Salt ausente, salt fixo em código, ou o mesmo salt para todos os usuários |
| IV e nonce | IV ou nonce constante no código, derivado de valor previsível, ou reutilizado com a mesma chave |
| Comparação de segredo | Comparação de token, HMAC, hash de senha ou assinatura com operador de igualdade comum, em vez de comparação de tempo constante |
| Verificação de certificado | Verificação de cadeia ou de hostname desligada (`rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`, gerenciador de confiança que aceita qualquer certificado) |
| Versão de TLS | TLS 1.0, TLS 1.1, SSLv2 ou SSLv3 configurados ou aceitos como versão mínima |

## Consulta de CVE para dependências

`cacador-dependencias` é o único subagente autorizado a executar comando de shell, restrito à
invocação dos scripts de consulta abaixo. Ordem de preferência:

1. **Base local**, pela skill `/nist:cve` empacotada neste plugin. Os scripts ficam em
   `${CLAUDE_PLUGIN_ROOT}/skills/cve/scripts/`; `cacador-dependencias` resolve o caminho na ordem
   documentada no próprio subagente, com fallback para `~/.claude/skills/cve/scripts/` e para
   `.claude/skills/cve/scripts/`. Havendo base local (padrão `~/.nvd/nvd.sqlite`), consulte com:

   `python <raiz-resolvida>/local_lookup.py --db ~/.nvd/nvd.sqlite --keyword <pacote> --min-severity MEDIUM`

   Obtenha a data do último sync com
   `python <raiz-resolvida>/local_lookup.py --db ~/.nvd/nvd.sqlite --stats`,
   registre-a no relatório e sinalize se for anterior a 7 dias.

   O caminho do script é sempre escrito por inteiro, a partir da raiz resolvida, porque é essa a
   forma coberta pelas regras `allow` de `PERMISSIONS.md`.

2. **API pública da NVD**, via `python <raiz-resolvida>/nvd_lookup.py`, quando a base local não
   estiver disponível. Consulte por nome e versão de cada dependência, respeitando o rate limit
   da NVD.

A chave de API da NVD, quando usada, vem da variável de ambiente `NVD_API_KEY` — nunca
hardcoded em arquivo versionado. Se a variável não existir, prossiga sem ela e registre no
Apêndice B do relatório que a consulta rodou em modo limitado.

Correlacione cada CVE encontrado ao controle **SP 800-218 RV.1**.
