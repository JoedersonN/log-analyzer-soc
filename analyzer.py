#!/usr/bin/env python3
"""
Log Analyzer for SOC
Analisa logs de sistema (auth.log, syslog, firewall) e detecta eventos suspeitos.
Gera relatório com alertas priorizados por severidade.
Autor: Joederson Neves | github.com/JoedersonN
"""

import re
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime


# ─── Regras de detecção ───────────────────────────────────────────────────────

RULES = {
    "brute_force": {
        "descricao": "Brute force SSH/login",
        "nivel":     "CRÍTICO",
        "threshold": 5,
    },
    "root_login": {
        "descricao": "Login direto como root",
        "nivel":     "ALTO",
        "threshold": 1,
    },
    "invalid_user": {
        "descricao": "Tentativa com usuário inexistente",
        "nivel":     "MÉDIO",
        "threshold": 3,
    },
    "sudo_escalation": {
        "descricao": "Escalada de privilégio via sudo",
        "nivel":     "ALTO",
        "threshold": 1,
    },
    "after_hours_login": {
        "descricao": "Login fora do horário comercial (antes das 7h ou após 20h)",
        "nivel":     "MÉDIO",
        "threshold": 1,
    },
    "session_opened": {
        "descricao": "Sessão aberta",
        "nivel":     "INFO",
        "threshold": 1,
    },
    "accepted_password": {
        "descricao": "Autenticação bem-sucedida",
        "nivel":     "INFO",
        "threshold": 1,
    },
}

# Padrões regex para parsing de auth.log (Linux)
PATTERNS = {
    "failed_password":   re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"),
    "invalid_user":      re.compile(r"Invalid user (\S+) from ([\d.]+)"),
    "accepted_password": re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"),
    "root_login":        re.compile(r"Accepted .+ for root from ([\d.]+)"),
    "sudo":              re.compile(r"sudo:.+USER=(\S+).+COMMAND=(.+)"),
    "session_opened":    re.compile(r"session opened for user (\S+)"),
    "timestamp":         re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"),
}


# ─── Parser de log ────────────────────────────────────────────────────────────

def parse_log(path: str) -> list:
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                event = {"raw": line, "lineno": lineno, "hour": None}

                # Extrai timestamp
                ts_match = PATTERNS["timestamp"].match(line)
                if ts_match:
                    try:
                        ts_str = ts_match.group(1)
                        ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                        event["hour"] = ts.hour
                        event["timestamp"] = ts_str
                    except ValueError:
                        pass

                # Classifica o evento
                if PATTERNS["failed_password"].search(line):
                    m = PATTERNS["failed_password"].search(line)
                    event["type"]    = "failed_password"
                    event["user"]    = m.group(1)
                    event["src_ip"]  = m.group(2)

                elif PATTERNS["invalid_user"].search(line):
                    m = PATTERNS["invalid_user"].search(line)
                    event["type"]   = "invalid_user"
                    event["user"]   = m.group(1)
                    event["src_ip"] = m.group(2)

                elif PATTERNS["root_login"].search(line):
                    m = PATTERNS["root_login"].search(line)
                    event["type"]   = "root_login"
                    event["user"]   = "root"
                    event["src_ip"] = m.group(1)

                elif PATTERNS["accepted_password"].search(line):
                    m = PATTERNS["accepted_password"].search(line)
                    event["type"]   = "accepted_password"
                    event["user"]   = m.group(1)
                    event["src_ip"] = m.group(2)

                elif PATTERNS["sudo"].search(line):
                    m = PATTERNS["sudo"].search(line)
                    event["type"]    = "sudo_escalation"
                    event["user"]    = m.group(1)
                    event["command"] = m.group(2).strip()
                    event["src_ip"]  = "local"

                elif PATTERNS["session_opened"].search(line):
                    m = PATTERNS["session_opened"].search(line)
                    event["type"] = "session_opened"
                    event["user"] = m.group(1)

                else:
                    event["type"] = "other"

                events.append(event)

    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {path}")
        sys.exit(1)

    return events


# ─── Análise e geração de alertas ────────────────────────────────────────────

def analyze(events: list) -> dict:
    failed_by_ip    = Counter()
    failed_by_user  = Counter()
    invalid_by_ip   = Counter()
    successful_logins = []
    root_logins     = []
    sudo_events     = []
    after_hours     = []
    alerts          = []

    for ev in events:
        t = ev.get("type", "other")

        if t == "failed_password":
            failed_by_ip[ev.get("src_ip", "?")] += 1
            failed_by_user[ev.get("user", "?")] += 1

        elif t == "invalid_user":
            invalid_by_ip[ev.get("src_ip", "?")] += 1

        elif t == "accepted_password":
            successful_logins.append(ev)
            hour = ev.get("hour")
            if hour is not None and (hour < 7 or hour >= 20):
                after_hours.append(ev)

        elif t == "root_login":
            root_logins.append(ev)

        elif t == "sudo_escalation":
            sudo_events.append(ev)

    # Alertas: brute force por IP
    for ip, count in failed_by_ip.items():
        if count >= RULES["brute_force"]["threshold"]:
            alerts.append({
                "nivel":    RULES["brute_force"]["nivel"],
                "tipo":     RULES["brute_force"]["descricao"],
                "detalhe":  f"IP {ip} — {count} falhas de autenticação",
                "ip":       ip,
            })

    # Alertas: usuário inválido
    for ip, count in invalid_by_ip.items():
        if count >= RULES["invalid_user"]["threshold"]:
            alerts.append({
                "nivel":   RULES["invalid_user"]["nivel"],
                "tipo":    RULES["invalid_user"]["descricao"],
                "detalhe": f"IP {ip} — {count} tentativas com usuário inexistente",
                "ip":      ip,
            })

    # Alertas: login root
    for ev in root_logins:
        alerts.append({
            "nivel":   RULES["root_login"]["nivel"],
            "tipo":    RULES["root_login"]["descricao"],
            "detalhe": f"IP {ev.get('src_ip', '?')} — login root direto detectado",
            "ip":      ev.get("src_ip", "?"),
        })

    # Alertas: sudo
    for ev in sudo_events:
        alerts.append({
            "nivel":   RULES["sudo_escalation"]["nivel"],
            "tipo":    RULES["sudo_escalation"]["descricao"],
            "detalhe": f"Usuário {ev.get('user','?')} executou: {ev.get('command','?')}",
            "ip":      "local",
        })

    # Alertas: login fora de horário
    for ev in after_hours:
        alerts.append({
            "nivel":   RULES["after_hours_login"]["nivel"],
            "tipo":    RULES["after_hours_login"]["descricao"],
            "detalhe": f"Usuário {ev.get('user','?')} de {ev.get('src_ip','?')} às {ev.get('timestamp','')}",
            "ip":      ev.get("src_ip", "?"),
        })

    # Ordena alertas por severidade
    ordem = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "INFO": 3}
    alerts.sort(key=lambda x: ordem.get(x["nivel"], 9))

    return {
        "total_events":      len(events),
        "failed_by_ip":      failed_by_ip,
        "failed_by_user":    failed_by_user,
        "successful_logins": successful_logins,
        "root_logins":       root_logins,
        "sudo_events":       sudo_events,
        "after_hours":       after_hours,
        "alerts":            alerts,
    }


# ─── Relatório ────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRÍTICO": "\033[91m",  # vermelho
    "ALTO":    "\033[93m",  # amarelo
    "MÉDIO":   "\033[94m",  # azul
    "INFO":    "\033[92m",  # verde
}
RESET = "\033[0m"


def print_report(data: dict, log_path: str, use_color: bool = True):
    def cor(nivel):
        return SEV_COLOR.get(nivel, "") if use_color else ""

    sep  = "=" * 60
    sep2 = "-" * 60
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(sep)
    print("  LOG ANALYZER FOR SOC — RELATÓRIO")
    print(sep)
    print(f"  Arquivo : {log_path}")
    print(f"  Data    : {ts}")
    print(f"  Eventos : {data['total_events']} linhas processadas")
    print(sep)

    # Resumo
    print("\n[RESUMO]")
    print(sep2)
    print(f"  Falhas de autenticação  : {sum(data['failed_by_ip'].values())}")
    print(f"  Logins bem-sucedidos    : {len(data['successful_logins'])}")
    print(f"  Logins root diretos     : {len(data['root_logins'])}")
    print(f"  Eventos sudo            : {len(data['sudo_events'])}")
    print(f"  Logins fora de horário  : {len(data['after_hours'])}")

    # Top IPs com falha
    if data["failed_by_ip"]:
        print("\n[TOP 5 — IPs COM MAIS FALHAS]")
        print(sep2)
        for ip, count in data["failed_by_ip"].most_common(5):
            print(f"  {ip:<20} {count:>5} falhas")

    # Top usuários atacados
    if data["failed_by_user"]:
        print("\n[TOP 5 — USUÁRIOS MAIS ATACADOS]")
        print(sep2)
        for user, count in data["failed_by_user"].most_common(5):
            print(f"  {user:<20} {count:>5} tentativas")

    # Logins bem-sucedidos
    if data["successful_logins"]:
        print(f"\n[LOGINS BEM-SUCEDIDOS — {len(data['successful_logins'])} total]")
        print(sep2)
        for ev in data["successful_logins"][:10]:
            print(f"  {ev.get('timestamp',''):>15}  {ev.get('user','?'):<15} de {ev.get('src_ip','?')}")
        if len(data["successful_logins"]) > 10:
            print(f"  ... e mais {len(data['successful_logins']) - 10}")

    # Sudo
    if data["sudo_events"]:
        print(f"\n[EVENTOS SUDO — {len(data['sudo_events'])} total]")
        print(sep2)
        for ev in data["sudo_events"]:
            print(f"  {ev.get('user','?'):<15} → {ev.get('command','?')[:50]}")

    # Alertas
    print(f"\n[ALERTAS — {len(data['alerts'])} encontrado(s)]")
    print(sep2)
    if not data["alerts"]:
        print("  Nenhum evento suspeito detectado.")
    else:
        for alerta in data["alerts"]:
            nivel = alerta["nivel"]
            print(f"  {cor(nivel)}[{nivel}]{RESET} {alerta['tipo']}")
            print(f"         {alerta['detalhe']}")

    print(f"\n{sep}")
    print("  Análise concluída.")
    print(sep)


def save_report(data: dict, log_path: str, output_path: str):
    import io, contextlib
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        print_report(data, log_path, use_color=False)
    with open(output_path, "w") as f:
        f.write(buffer.getvalue())
    print(f"\n[*] Relatório salvo em: {output_path}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analisa logs de sistema Linux (auth.log) e detecta eventos suspeitos."
    )
    parser.add_argument("log", help="Caminho para o arquivo de log (ex: /var/log/auth.log)")
    parser.add_argument(
        "-o", "--output",
        help="Salvar relatório em arquivo .txt (opcional)",
        default=None
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Desativar cores no terminal"
    )
    args = parser.parse_args()

    print(f"[*] Processando: {args.log}")
    events = parse_log(args.log)
    print(f"[*] {len(events)} eventos carregados. Analisando...\n")

    data = analyze(events)
    print_report(data, args.log, use_color=not args.no_color)

    if args.output:
        save_report(data, args.log, args.output)


if __name__ == "__main__":
    main()
