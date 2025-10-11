<div align="left">

<a href="https://pepy.tech/project/moriarty-project">
  <img src="https://img.shields.io/badge/DOWNLOADS-4.2K-00D26A?style=for-the-badge&labelColor=2D2D2D&logo=python&logoColor=white" alt="Downloads"/>
</a>

<a href="https://pypi.org/project/moriarty-project/">
  <img src="https://img.shields.io/pypi/v/moriarty-project?style=for-the-badge&label=LATEST%20RELEASE&color=0094FF&labelColor=2D2D2D&logo=pypi&logoColor=white" alt="Latest Release"/>
</a>

<a href="https://github.com/DonatoReis/moriarty/stargazers">
  <img src="https://img.shields.io/github/stars/DonatoReis/moriarty?style=for-the-badge&label=STARS&color=FFD700&labelColor=2D2D2D&logo=github&logoColor=white" alt="Stars"/>
</a>

# Moriarty

### Ferramenta Avançada de OSINT e Segurança

*Ferramenta avançada de reconhecimento e análise de segurança para investigações OSINT e testes de penetração*

<img src="./assets/img/terminal.png" alt="Moriarty Banner" width="90%"/>

</div>

</td>
<td width="50%">

## 📑 Índice

- [🌟 Recursos Principais](#-recursos-principais)
- [🚀 Instalação](#-instalação)
- [💻 Uso Básico](#-uso-básico)
- [🔍 Comandos](#-comandos)
- [🛡️ Segurança](#️-recursos-de-segurança)
- [🤝 Contribuindo](#-contribuindo)
- [📄 Licença](#-licença)

</td>
<td width="50%">

## 🌟 Recursos Principais

<table>
<tr>

</td>
<td width="50%">

### 🔍 Reconhecimento Passivo
- Coleta de informações OSINT
- Descoberta de subdomínios
- Análise de certificados SSL/TLS
- Metadados WHOIS/RDAP

</td>
<td width="50%">

### 🛡️ Varredura de Segurança
- Detecção de serviços e portas
- Identificação de tecnologias web
- Scanner de vulnerabilidades
- Detecção de WAF/IPS/IDS

</td>
</tr>
<tr>

</td>
<td width="50%">

### 📧 Análise de E-mail
- Validação DNS/SMTP
- Investigação em múltiplas fontes
- Verificação de vazamentos
- Análise de reputação

</td>
<td width="50%">

### 🎯 Inteligência de Ameaças
- Análise de IOCs
- Verificação de credenciais
- Reputação de domínios
- Detecção de ameaças conhecidas

</td>
</tr>
</table>

</td>
<td width="50%">

## 🚀 Instalação

### Pré-requisitos

```bash
Python 3.13+ | pip | pipx (recomendado)
```

### Via pipx (Recomendado)

```bash
# Instalar usando pipx
pipx install moriarty-project

# Verificar instalação
moriarty --help
```

### Via pip

```bash
# Instalação global
pip install moriarty-project

# Instalação para usuário
pip install --user moriarty-project
```

### Para Desenvolvimento

```bash
# Clonar repositório
git clone https://github.com/DonatoReis/moriarty.git
cd moriarty

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Instalar em modo desenvolvimento
pip install -e .
pip install -r requirements-dev.txt
```

---

## 💻 Uso Básico

### Estrutura de Comandos

```bash
moriarty [OPÇÕES_GLOBAIS] COMANDO [ARGUMENTOS] [OPÇÕES]
```

### Opções Globais

| Opção | Descrição | Padrão |
|-------|-----------|--------|
| `--verbose` | Logs detalhados | `False` |
| `--quiet` | Suprimir saída | `False` |
| `--concurrency INT` | Tarefas concorrentes | `50` |
| `--timeout FLOAT` | Timeout (segundos) | `8.0` |
| `--proxy URL` | Proxy HTTP/SOCKS | - |
| `--format` | Formato de saída | `table` |
| `--output PATH` | Salvar em arquivo | - |

</td>
<td width="50%">

## 🔍 Comandos

### 📧 E-mail

<details>
<summary><b>email check</b> - Validar endereço de e-mail</summary>

```bash
# Uso básico
moriarty email check usuario@exemplo.com

# Com opções
moriarty email check --verbose usuario@exemplo.com --format json --output resultado.json
```

</details>

<details>
<summary><b>email investigate</b> - Investigação aprofundada</summary>

```bash
# Investigar em múltiplas fontes
moriarty email investigate usuario@exemplo.com --verbose
```

</details>

### 👤 Usuário

<details>
<summary><b>user enum</b> - Enumerar nome de usuário</summary>

```bash
# Verificar disponibilidade
moriarty user enum nomeusuario

# Em sites específicos
moriarty user enum nomeusuario --sites github,twitter,instagram --output resultados.json
```

</details>

### 🌐 Domínio

<details>
<summary><b>domain scan</b> - Varredura completa</summary>

```bash
# Varredura completa
moriarty domain scan example.com --stealth 2 --threads 50

# Módulos específicos
moriarty domain scan example.com --modules dns,ports,ssl
```

**Opções:**
- `--modules`: all, dns, subdiscover, wayback, ports, ssl, crawl, fuzzer, template-scan, vuln-scan, waf-detect
- `--stealth`: Nível de stealth (0-4)
- `--threads`: Threads concorrentes
- `--timeout`: Timeout em segundos

</details>

<details>
<summary><b>domain recon</b> - Reconhecimento passivo</summary>

```bash
moriarty domain recon example.com --output results.json
```

</details>

### 🎯 Inteligência

<details>
<summary><b>intel ioc</b> - Análise de IOCs</summary>

```bash
moriarty intel ioc --file iocs.txt --output report.html
```

</details>

### 🌐 Rede

| Comando | Descrição |
|---------|-----------|
| `network dns` | Consultas DNS avançadas |
| `network tls` | Análise TLS/SSL |
| `network rdap` | Consultas RDAP |

### 🛠️ Ferramentas

| Comando | Descrição |
|---------|-----------|
| `tools template` | Gerenciamento de templates |
| `tools waf` | Testes de detecção WAF |

</td>
<td width="50%">

## 🛠️ Exemplos Práticos

```bash
# 1. Varredura básica com stealth
moriarty domain scan example.com --stealth 2 --threads 50

# 2. Reconhecimento passivo completo
moriarty domain recon example.com --output results.json --format json

# 3. Verificação de e-mail com investigação
moriarty email check user@example.com --verbose
moriarty email investigate user@example.com

# 4. Análise de IOCs com relatório HTML
moriarty intel ioc --file iocs.txt --output report.html

# 5. Enumeração de usuário em redes sociais
moriarty user enum johndoe --sites github,twitter,linkedin
```

</td>
<td width="50%">

## 🛡️ Recursos de Segurança

### Modo Profissional

```bash
moriarty --professional-mode domain scan example.com
```

### Segurança e Privacidade

- ✅ Conexões criptografadas (HTTPS/TLS)
- ✅ Redação automática de PII
- ✅ Suporte a proxies e Tor
- ✅ Assinatura digital de resultados
- ✅ Modo stealth avançado

</td>
<td width="50%">

## 🤝 Contribuindo

Contribuições são bem-vindas! 🎉

1. Fork o repositório
2. Crie uma branch (`git checkout -b feature/NovaFeature`)
3. Commit suas mudanças (`git commit -m 'Add: Nova feature'`)
4. Push para a branch (`git push origin feature/NovaFeature`)
5. Abra um Pull Request

### Diretrizes

- Siga o [Guia de Estilo](CONTRIBUTING.md)
- Adicione testes para novas funcionalidades
- Atualize a documentação
- Mantenha o código limpo e documentado

</td>
<td width="50%">

## 📄 Licença

Distribuído sob a licença MIT. Veja [`LICENSE`](LICENSE) para mais informações.

</td>
<td width="50%">

## 🎯 Roadmap

- [ ] Interface Web (Dashboard)
- [ ] API REST completa
- [ ] Plugins de extensão
- [ ] Integração com mais fontes OSINT
- [ ] Relatórios automatizados
- [ ] Modo colaborativo multi-usuário

</td>
<td width="50%">

## 🌟 Agradecimentos

Obrigado a todos os [contribuidores](https://github.com/DonatoReis/moriarty/graphs/contributors) que ajudam a tornar o Moriarty melhor!

</td>
<td width="50%">

<div align="center">

**[⬆ Voltar ao topo](#moriarty)**

*Desenvolvido com ❤️ pela comunidade*

</div>
