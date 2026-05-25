# ☠️ REAPER
### Recon, Exploit, Analysis & Post-exploitation Reporting Engine

> Ferramenta de terminal para Kali Linux que guia o utilizador pelos **7 passos de um pentest** — com motor de inteligência, árvore de decisão por vector de ataque, e geração de relatório final em PDF/TXT.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-2023%2B-557C94?style=flat-square&logo=kalilinux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Em_desenvolvimento-yellow?style=flat-square)

---

## 📸 Preview

```
╔══════════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗           ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗          ║
║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝          ║
║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗          ║
║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║          ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝          ║
║          Recon · Exploit · Analysis · Post-exploitation      ║
║                         by Craveiro                          ║
╚══════════════════════════════════════════════════════════════╝
```

---

## ⚡ O que é o REAPER?

O REAPER é uma **framework de pentest em terminal**, inspirado no estilo do Metasploit, que:

- Guia o utilizador pelos **7 passos de um ataque** de forma estruturada
- Tem um **Motor de Inteligência** que analisa os outputs do nmap e sugere vectores de ataque automaticamente
- Possui uma **árvore de decisão** por serviço — FTP, SSH, HTTP, SMB, SQLi, Privesc, e mais
- Permite **executar ferramentas reais** (nmap, hydra, gobuster, sqlmap, linpeas, etc.) directamente no terminal
- **Guarda o progresso** do projecto em JSON e gera **relatório final em PDF ou TXT**

---

## 🗂️ Os 7 Passos

| # | Fase | Ferramentas |
|---|------|-------------|
| 1 | 🔍 Reconhecimento | whois, dig, theHarvester, netdiscover, nslookup |
| 2 | 📡 Scanning | nmap (básico, completo, UDP, vuln), masscan |
| 3 | 🔎 Enumeração | gobuster, feroxbuster, ffuf, nikto, wpscan, enum4linux, smbclient, dirb |
| 4 | 🐛 Análise de Vulnerabilidades | searchsploit, nuclei, vulners, msfconsole |
| 5 | 💥 Exploração | hydra, john, hashcat, sqlmap, msfvenom |
| 6 | 🏠 Pós-Exploração | linpeas, sudo -l, SUID, crontab, capabilities, PATH hijacking |
| 7 | 📄 Relatório | Geração automática PDF / TXT com toda a informação recolhida |

---

## 🧠 Motor de Inteligência

O REAPER inclui um motor de análise que:

1. **Analisa o output do nmap** — detecta automaticamente os serviços activos
2. **Apresenta os vectores de ataque disponíveis** para cada serviço encontrado
3. **Guia passo a passo** com dicas contextuais antes de cada técnica
4. **Regista o resultado** (✔ sucesso / ✘ falhou) e sugere o próximo caminho
5. **Nunca fecha a árvore** — podes sempre voltar e tentar outro vector

**Vectores suportados:**

| Vector | Técnicas |
|--------|----------|
| 📁 FTP | Acesso anónimo, brute force, exploits por versão |
| 🔐 SSH | Enumeração de users, brute force, login, exploits |
| 🌐 HTTP/Web | nikto, gobuster, SQLi, LFI, upload de shell, WordPress |
| 📂 SMB | enum4linux, EternalBlue, smbclient, pass-the-hash |
| 🗄️ SQL/DB | MySQL sem password, brute force, LOAD_FILE |
| ⬆️ Privesc | linpeas, sudo, SUID, cron, capabilities, PATH, kernel |
| 🔓 Hashes | john, hashcat, unshadow |

---

## 🛠️ Instalação

### Pré-requisitos

- **Kali Linux** (recomendado) ou qualquer distro Linux com Python 3.8+
- As ferramentas de pentest já incluídas no Kali (nmap, hydra, gobuster, etc.)

### Passo a Passo

**1. Clonar o repositório**
```bash
git clone https://github.com/SEU_USERNAME/REAPER.git
cd REAPER
```

**2. Instalar dependências Python**
```bash
pip install rich reportlab --break-system-packages
```

> No Kali Linux 2023+ é necessário o flag `--break-system-packages` por causa do ambiente gerido externamente.

**3. Dar permissão de execução (opcional)**
```bash
chmod +x reaper.py
```

**4. Correr o REAPER**
```bash
python3 reaper.py
```

---

## 🚀 Utilização Rápida

```bash
# Clonar e instalar
git clone https://github.com/SEU_USERNAME/REAPER.git
cd REAPER
pip install rich reportlab --break-system-packages

# Correr
python3 reaper.py
```

### Fluxo básico:

```
1. Menu Principal → [1] Novo Projecto
2. Definir nome e IP do alvo
3. Percorrer as fases (1 a 7)
4. Em cada fase → escolher ferramenta → preencher parâmetros → executar
5. Menu Principal → [I] Motor de Inteligência → analisar output do nmap
6. Seguir a árvore de decisão consoante os vectores encontrados
7. Menu Principal → [R] Relatório → gerar PDF ou TXT
```

---

## 📦 Dependências

| Pacote | Versão | Para quê |
|--------|--------|----------|
| `rich` | ≥ 13.0 | Interface de terminal (cores, tabelas, menus) |
| `reportlab` | ≥ 4.0 | Geração de relatórios em PDF |

As restantes ferramentas (nmap, hydra, gobuster, etc.) já estão incluídas no Kali Linux por defeito.

---

## ⚠️ Aviso Legal / Disclaimer

> **Este projecto foi desenvolvido exclusivamente para fins educativos, em ambiente controlado, como parte de formação em cibersegurança.**
>
> O REAPER deve ser usado **apenas em sistemas para os quais tens autorização explícita** por escrito. A utilização desta ferramenta em sistemas sem autorização é **ilegal** e contrária à ética profissional.
>
> O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

---

## 👤 Autor

**Craveiro**
Formação em Cibersegurança — Pentest, Network Security, CTF

[![LinkedIn](https://img.shields.io/badge/LinkedIn-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/SEU_PERFIL)
[![GitHub](https://img.shields.io/badge/GitHub-black?style=flat-square&logo=github)](https://github.com/SEU_USERNAME)

---

## 📝 Licença

Este projecto está licenciado sob a [MIT License](LICENSE).

---

*"Know your enemy and know yourself." — Sun Tzu*
