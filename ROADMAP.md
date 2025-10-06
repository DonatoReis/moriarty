# 📍 Roadmap de Evolução do Modo `domain`

Este arquivo consolida as próximas evoluções planejadas para o Moriarty, dividindo o trabalho em três linhas prioritárias. Cada item traz um conjunto de entregas e um checklist para acompanhamento.

---

## ✅ Recursos Já Entregues (Resumo)
- Subdomain Discovery com integrações (VirusTotal, SecurityTrails, Shodan), cache com TTL e wordlist 1000+.
- Wayback Discovery com filtros de status, extração de parâmetros, detecção de URLs admin e exportações dedicadas.
- Template Scanner com 50+ templates, DSL estendida, suporte a raw requests, auto_fuzz/fuzz, validação/linting.
- Pipeline Orchestrator com paralelismo, retries, checkpoints, logging estruturado e notificações.
- Stealth Mode v2.0 com health check, rotação/failover, randomização fingerprint, spoofing TCP/IP, Tor/I2P.
- WAF Detector com técnicas de bypass, cadeias, rate limiting, IDS/IPS evasion e CAPTCHA solver.
- Cache Inteligente com backend memória/SQLite, LRU, warmup, métricas e integração com ConfigManager.

---

## 🔁 Prioridade 1 — Recon Passiva + Contexto Inteligente
| Item | Descrição | Status |
|------|-----------|--------|
| [ ] | Integração PassiveTotal (API de passive DNS) | [ ]
| [ ] | Integração certspotter / crt observability | [ ]
| [ ] | Integração Censys (hosts e certificados) | [ ]
| [ ] | Integração haveibeenpwned / LeakPeek (credenciais) | [ ]
| [ ] | Ampliação SecurityTrails (dados históricos) | [ ]
| [ ] | Integração Spyse / LeakIX (threat intel) | [ ]
| [ ] | Fingerprinting de tecnologias (headers, `manifest.json`, `/robots.txt`, `/wp-json`, `/graphql`) | [ ]
| [ ] | Motor básico estilo Wappalyzer (mapear tecnologias, versões) | [ ]
| [ ] | Regras de reputação (listas ransomware, boletins CERT, CVEs recentes) | [ ]
| [ ] | Coleta WHOIS / RDAP consolidada por pipeline | [ ]

> **Objetivo:** enriquecer a visão passiva antes de qualquer ataque ativo, alimentando priorização e seleção de módulos.

---

## 🚀 Prioridade 2 — Exploração Web e Cobertura de Vulnerabilidades
| Item | Descrição | Status |
|------|-----------|--------|
| [ ] | Wrapper de port scanning (masscan/nmap) com perfis “rápido”/“completo” | [ ]
| [ ] | Fingerprint de banners e diffs entre execuções | [ ]
| [ ] | Web crawler leve (rotas, formulários, parâmetros) com modo stealth | [ ]
| [ ] | Enumeração de endpoints e parâmetros para fuzzing posterior | [ ]
| [ ] | Seleção dinâmica de templates com base no fingerprint | [ ]
| [ ] | Auto_fuzz de endpoints descobertos pelo crawler | [ ]
| [ ] | Ingestão automatizada de templates externos (ex.: projectdiscovery/nuclei) | [ ]
| [ ] | Replays autenticados (cookies, tokens, fluxo login→ação) | [ ]
| [ ] | Integração do WAF bypass antes de scanners agressivos | [ ]

> **Objetivo:** transformar o modo `domain` em pipeline automático de descoberta → exploração controlada.

---

## 🤖 Prioridade 3 — Orquestração, Automação e Entrega
| Item | Descrição | Status |
|------|-----------|--------|
| [ ] | Presets `moriarty domain recon <alvo>` / `exploit` / `cloud` acionando pipelines prontos | [ ]
| [ ] | Expressões condicionais avançadas em stages (ex.: if `s3_public` → roda módulo X) | [ ]
| [ ] | Timeline/versionamento de execuções (SQLite/Postgres) com diffs | [ ]
| [ ] | Relatórios HTML/PDF com gráficos, top achados e links acionáveis | [ ]
| [ ] | Integração com Slack/Jira/ServiceNow (alertas e tickets automáticos) | [ ]
| [ ] | CLI wizard (`moriarty domain pipeline new --preset`) gerando YAML base | [ ]
| [ ] | Flag global `--stealth-level` que aciona StealthMode para todos os módulos web | [ ]
| [ ] | Backend Redis opcional para caches compartilhados | [ ]
| [ ] | Diagnóstico de dependências/API keys faltantes | [ ]
| [ ] | Pipelines de teste (DVWA, Juice Shop etc.) para regressão contínua | [ ]

---

## 📌 Próximos Passos Imediatos
1. **Recon Passiva (lote inicial)**: priorizar PassiveTotal, Censys, haveibeenpwned e fingerprint básico (headers + `/robots.txt`).
2. **Exploração Web**: implementar wrapper de port scanning e crawler leve em paralelo.
3. **Automação**: esboçar presets `moriarty domain recon` / `exploit` e definir formato do relatório.

Cada etapa trará tarefas menores registradas nesta checklist; ao terminar, marque `[x]` e adicione notas na mesma linha ou referência a PR/commit.

---

> **Como usar:** mantenha este arquivo versionado no repositório. Ao concluir uma entrega, atualize o checkbox correspondente e adicione qualquer anotação útil (ex.: commit hash, doc, PR). Isso ajuda a equipe a acompanhar o progresso sem precisar ler todo o histórico de mudanças.


Pense passo a passo e implemente tudo abaixo de forma inteligente, completa e avançada. Configure todas as flags, comandos e deixe tudo pronto e perfeito.



1. Cobertura Passiva + Contexto Inteligente
Expandir fontes OSINT: além de Wayback e subdomains, incluir verificações automáticas em PassiveTotal, certspotter, censys, securitytrails (dados históricos), threat intelligence (AlienVault, Spyse, LeakIX), busca por credenciais expostas (haveibeenpwned, LeakPeek). Muitas dessas integrações podem reutilizar o mesmo ConfigManager de API keys.
Fingerprint de tecnologias: coletar headers, arquivos manifest.json, respostas /wp-json, /graphql, /robots.txt e rodar detectores (Wappalyzer-like). Isso orienta os templates/fuzzers que serão disparados depois.
Integração com reputação: condicionar pipelines a sinais de risco (por exemplo, se a organização aparece em listas de Ransomware, CVEs recentes, boletins CERT).
2. Varredura Ativa e Cobertura de Vulnerabilidades
Port scanning especializado: substituir o “placeholder” do módulo ports por algo real (masscan/nmap via wrapper) com perfis (rápido x completo), fingerprint de banners e diffs entre execuções.
Web crawling leve + enumeração: incorporar --crawl de verdade (identificar rotas, forms, parâmetros) como pré-etapa antes do template-scan.
Biblioteca de templates dinâmica:
Classificar por tags (cloud, CMS, APIs, mobile) e permitir seleção inteligente baseada no fingerprint coletado.
Introduzir variações automáticas (auto_fuzz) em endpoints descobertos durante o crawl.
Ampliar a biblioteca para incluir explorações de novas CVEs conforme divulgadas (automatizar ingestão de YAMLs externos confiáveis, como projectdiscovery/nuclei).
Teste de WAF/BYPASS integrado ao pipeline: após detectar WAF, usar as cadeias de bypass como pré-processamento antes de rodar scanners agressivos.
Estender TemplateExecutor para suportar contexto entre requests (cookies, tokens) e replays de workflows (ex.: login → ação autenticada).
3. Orquestração, Automação e Entrega
Pipelines prontos sob demanda: criar perfis modoRecon, modoExploit, modoCloud etc., que o usuário dispara com algo como moriarty domain recon example.com — internamente acionaria o PipelineOrchestrator com stages adequados.
Inteligência de fluxo: permitir expressões condicionais baseadas nos artefatos coletados (ex.: “se encontramos bucket S3 público, roda módulo X”). O DSL já é usado para matchers; dá para usar lógica similar em condições de stage.
Timeline e versionamento: guardar os resultados das execuções anteriores (ex.: via SQLite/Postgres) para comparar deltas (novos subdomínios, portas recém-abertas, mudanças no WAF).
Relatórios enriquecidos: gerar outputs resumidos (HTML/PDF) com gráficos de descobertas, matando o gap entre CLI e repasse para terceiros.
Integração com tickets/alertas: conectores para Jira, Slack, ServiceNow acionados conforme políticas (ex.: OWASP risco >= “medium” abre issue automaticamente).
Modo “headless stealth” unificado: permitir moriarty domain scan --stealth-level 3 que acione automaticamente o StealthMode na requisição de todos os módulos web.
4. Qualidade, Escalabilidade e DX
Redis como cache compartilhado: permitir backend Redis nos caches (DNSCache, subdomains) para ambientes distribuídos.
Controle de dependências externas: ao detectar API key faltando, sugerir automaticamente as variáveis/arquivos a preencher.
Testes end-to-end: criar pipelines de exemplo com targets de laboratório (DVWA, Juice Shop, etc.) para validar continuamente as integrações.
CLI “wizard” / presets: ajudar o usuário a montar pipelines via moriarty domain pipeline new --preset recon gerando YAML inicial escalável.
5. Fechando lacunas específicas
Wayback CLI: --status já implementado; pode adicionar flags --params, --admins para gravar outputs específicos direto da CLI (chamando export_parameters, export_admin_urls).
DSL avançado: com as novas funções, dá para escrever expressões ricas (status_in(200,201) and contains(body,'"version"') and json_get("meta.active") == True). Futuramente, dá para incluir agregações (sum, avg) ou contexto cross-response.
Lista wordlist: revisar duplicatas e organizar por categorias (infra, cloud, APIs) para gerar wordlists segmentadas (melhora brute force).
Coleta whois, tecnlogias,

🎯 Exemplos de COMANDOS DE RECONHECIMENTO

Varredura de Portas e Serviços

bash
nmap -Pn -n --open -sS -sV -sC
nmap -sV -p 25,587 --script smtp-commands,smtp-open-relay,smtp-enum-users
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-users
nmap -p22,2222 --script ssh2-enum-algos
nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.mode=VRFY
sudo nmap -p 25,143,993,443 --script ssl-cert,ssl-enum-ciphers -Pn
nmap -sV -p 110,143,993,995 --script imap-capabilities,pop3-capabilities,ssl-cert
Análise SSL/TLS

bash
openssl s_client -starttls smtp -connect :25 -crlf
openssl s_client -starttls smtp -connect :25 -cipher 'ECDHE:!aNULL:!eNULL' -crlf
openssl s_client -connect :993 -crlf
openssl s_client -connect :993 -crlf -showcerts
🔍 COMANDOS DE ENUMERAÇÃO WEB

WordPress

bash
curl -I -s /xmlrpc.php
curl -s -H "Content-Type: text/xml" --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
curl -s /wp-content/themes/betheme/style.css | grep -i 'Version\|Theme'
curl -s /readme.html | head -n 40
curl -s /robots.txt
curl -s /wp-json/wp/v2/users | jq .
Fingerprinting

bash
whatweb
💀 COMANDOS DE EXPLORAÇÃO

Testes de Autenticação

bash
ssh -vv -p 22 nobody@
mysql -h -P 3306 -u root --password='' --ssl=0
Serviços de Email

bash
swaks --to target@example.com --from attacker@external.test --server :25 --timeout 10
Testes XSS

bash
python3 xsstrike.py -u "/fileman/index.html?lang=" --crawl --blind --timeout 15
🕵️ COMANDOS OSINT

Informações de Domínio

bash
whois
dig +short TXT
Análise de Certificados

bash
cat logs/*_crtsh.json
🔬 COMANDOS DE ANÁLISE

Configurações Expostas

bash
curl -s /.git/config
curl -s /fileman/conf.json
curl -s | sed -n '1,10p'
Testes de Conexão

bash
ssh -vv -p 22