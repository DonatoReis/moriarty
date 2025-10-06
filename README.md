# Moriarty - Ferramenta Avançada de OSINT e Segurança

<!-- Banner -->
<p align="center">
  <a href="https://pypi.org/project/moriarty-project/">
    <img
      src="./assets/img/moriarty-banner.png"
      alt="Moriarty OSINT - Ferramenta avançada de reconhecimento e análise de segurança"
      width="60%"
      style="border: 1px solid #2d2d2d; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
  </a>
</p>

<!-- Subtítulo -->
<p align="center">
  Ferramenta avançada de reconhecimento e análise de segurança para investigações OSINT e testes de penetração.
</p>

<!-- Badges -->
<p align="center">
  <a href="https://pypi.org/project/moriarty-project/">
    <img src="https://img.shields.io/pypi/v/moriarty-project?color=blue&label=PyPI" alt="PyPI version">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/pypi/pyversions/moriarty-project?color=blue" alt="Python Versions">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
  <a href="https://github.com/DonatoReis/moriarty/stargazers">
    <img src="https://img.shields.io/github/stars/DonatoReis/moriarty?style=social" alt="GitHub stars">
  </a>
</p>

<p align="center">
  <a href="#instalação">Instalação</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#uso">Uso</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#comandos">Comandos</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#contribuindo">Contribuindo</a>
</p>

## 🌟 Recursos Principais

- **Reconhecimento Passivo Avançado**
  - Coleta de informações de múltiplas fontes OSINT
  - Descoberta de subdomínios
  - Análise de certificados SSL/TLS
  - Coleta de metadados WHOIS/RDAP

- **Varredura de Segurança**
  - Varredura de portas com detecção de serviços
  - Detecção de tecnologias web
  - Identificação de vulnerabilidades comuns
  - Teste de WAF/IPS/IDS

- **Análise de Ameaças**
  - Verificação de credenciais vazadas
  - Análise de reputação de domínios
  - Detecção de ameaças conhecidas

## 🚀 Instalação

### Pré-requisitos
- Python 3.13+ (versão mínima suportada)
- pip (gerenciador de pacotes do Python)

### Instalação via pipx (recomendado para usuários)
```bash
# Instalar usando pipx (recomendado para isolar o ambiente)
pipx install moriarty-project

# OU para instalar uma versão específica
# pipx install moriarty-project 0.1.5

# Verificar a instalação
moriarty --help
```

### Instalação via pip (usuários avançados)
```bash
# Instalar globalmente
pip install moriarty-project

# OU para instalar para o usuário atual
# pip install --user moriarty

# Verificar a instalação
moriarty --help
```

### Instalação para desenvolvimento
```bash
# Clonar o repositório
git clone https://github.com/DonatoReis/moriarty.git
cd moriarty

# Criar e ativar ambiente virtual (opcional, mas recomendado)
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instalar em modo de desenvolvimento
pip install -e .

# Instalar dependências de desenvolvimento
pip install -r requirements-dev.txt
```

## 💻 Uso Básico

### Estrutura de Comandos
```
moriarty [OPÇÕES] COMANDO [ARGUMENTOS] [OPÇÕES-DO-COMANDO]
```

### Opções Globais
- `--sign`: Assinar digitalmente os resultados
- `--verbose`: Mostrar informações detalhadas de execução
- `--concurrency INT`: Número máximo de tarefas concorrentes (padrão: 50)
- `--timeout FLOAT`: Timeout por requisição em segundos (padrão: 8.0)
- `--proxy URL`: Usar proxy HTTP/SOCKS
- `--format FORMAT`: Formato de saída (table, json, yaml)
- `--output PATH`: Salvar saída em arquivo
- `--verbose`: Habilitar logs detalhados
- `--quiet`: Suprimir saída não crítica

## 🔍 Comandos e Exemplos

### 📧 Comandos de E-mail

#### `email check`
Valida um endereço de e-mail usando heurísticas de DNS e SMTP.

**Uso:**
```bash
moriarty email check usuario@exemplo.com
```

**Exemplo com opções:**
```bash
# Verificar e-mail com modo verboso
moriarty email check --verbose usuario@exemplo.com

# Verificar e-mail e salvar resultado em JSON
moriarty email check usuario@exemplo.com --format json --output resultado.json
```

#### `email investigate`
Investiga um e-mail em múltiplas fontes (Gravatar, redes sociais, vazamentos).

**Uso:**
```bash
moriarty email investigate usuario@exemplo.com
```

**Exemplo:**
```bash
# Investigação completa com saída detalhada
moriarty email investigate --verbose usuario@exemplo.com
```

### 👤 Comandos de Usuário

#### `user enum`
Enumera um nome de usuário em múltiplos sites.

**Uso:**
```bash
moriarty user enum nomeusuario
```

**Exemplo com opções:**
```bash
# Verificar disponibilidade em sites específicos
moriarty user enum nomeusuario --sites github,twitter,instagram

# Salvar resultados em um arquivo
moriarty user enum nomeusuario --output resultados_usuario.json
```

## 🛠️ Comandos Principais

### `domain`
Comandos para análise de domínios e redes.

#### `domain scan`
Varredura completa de domínio/IP.

**Uso:**
```bash
moriarty domain scan example.com [OPÇÕES]
```

**Opções:**
- `--modules`: Módulos a serem executados (all,dns,subdiscover,wayback,ports,ssl,crawl,fuzzer,template-scan,vuln-scan,waf-detect)
- `--stealth`: Nível de stealth (0-4)
- `--threads`: Número de threads concorrentes
- `--timeout`: Timeout em segundos

#### `domain recon`
Reconhecimento passivo de domínio.

**Uso:**
```bash
moriarty domain recon example.com [OPÇÕES]
```

### `email`
Ferramentas para análise de endereços de e-mail.

#### `email check`
Verifica a validade e informações de um e-mail.

**Uso:**
```bash
moriarty email check user@example.com
```

### `intel`
Ferramentas de inteligência de ameaças.

#### `intel ioc`
Analisa Indicadores de Comprometimento (IOCs).

**Uso:**
```bash
moriarty intel ioc --file iocs.txt
```

## 🛠️ Exemplos

### 1. Varredura Básica de Domínio
```bash
moriarty domain scan example.com --stealth 2 --threads 50
```

### 2. Reconhecimento Passivo
```bash
moriarty domain recon example.com --output results.json
```

### 3. Verificação de E-mail
```bash
moriarty email check user@example.com --format json
```

### 4. Análise de IOC
```bash
moriarty intel ioc --file iocs.txt --output report.html
```

## 🛡️ Recursos de Segurança

### Modo Profissional
Ative o modo profissional para habilitar salvaguardas adicionais:
```bash
moriarty --professional-mode domain scan example.com
```

### Criptografia e Privacidade
- Suporte a conexões criptografadas (HTTPS/TLS)
- Opção para redação de PII (Informações Pessoais Identificáveis)
- Suporte a proxies e Tor

## 🤝 Contribuindo

Contribuições são bem-vindas! Siga estes passos:

1. Faça um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Faça commit das suas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Faça push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.

## 📧 Contato

Equipe Moriarty - [contato@moriarty.dev](mailto:contato@moriarty.dev)

Link do Projeto: [https://github.com/DonatoReis/moriarty](https://github.com/DonatoReis/moriarty)

---

Este README foi gerado em 06/10/2023. Consulte a documentação online para informações mais recentes.

## 🔍 Índice de Comandos Detalhados

### Comandos de Domínio
- `domain scan`: Varredura completa de domínio
- `domain recon`: Reconhecimento passivo
- `domain subdomains`: Enumeração de subdomínios
- `domain wayback`: Análise histórica via Wayback Machine
- `domain ports`: Varredura de portas
- `domain crawl`: Web crawling

### Comandos de E-mail
- `email check`: Validação de e-mail usando DNS/SMTP
- `email investigate`: Análise aprofundada em múltiplas fontes (Gravatar, redes sociais, vazamentos)

### Comandos de Usuário
- `user enum`: Verifica disponibilidade de nome de usuário em múltiplos sites

### Comandos de Inteligência
- `intel ioc`: Análise de IOCs
- `intel threat`: Verificação de ameaças

### Comandos de Rede
- `network dns`: Consultas DNS
- `network tls`: Análise TLS/SSL
- `network rdap`: Consultas RDAP

### Ferramentas
- `tools template`: Gerenciamento de templates
- `tools waf`: Testes de WAF

---

Para obter ajuda detalhada sobre qualquer comando, use:
```bash
moriarty [comando] --help
```
