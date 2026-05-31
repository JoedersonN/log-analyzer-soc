# log-analyzer-soc

Ferramenta Python para análise de logs de sistema Linux com detecção automática de eventos suspeitos — desenvolvida com foco em operações SOC Tier 1.

Desenvolvida como parte do meu portfólio em Blue Team / SOC.

---

## O que faz

Processa arquivos `auth.log` (Linux) e detecta automaticamente:

| Detecção | Severidade |
|---|---|
| Brute force SSH (5+ falhas do mesmo IP) | 🔴 CRÍTICO |
| Login direto como root via SSH | 🟠 ALTO |
| Escalada de privilégio via sudo | 🟠 ALTO |
| Tentativas com usuário inexistente | 🟡 MÉDIO |
| Login fora do horário comercial (antes 7h / após 20h) | 🟡 MÉDIO |

Além dos alertas, gera relatório completo com:
- Resumo de eventos (falhas, logins, sudo)
- Top IPs com mais tentativas de autenticação
- Top usuários mais atacados
- Lista de logins bem-sucedidos com timestamp
- Todos os eventos sudo com comando executado

---

## Instalação

```bash
git clone https://github.com/JoedersonN/log-analyzer-soc
cd log-analyzer-soc
```

Sem dependências externas — usa apenas a biblioteca padrão do Python 3.

---

## Uso

```bash
# Analisar log real do sistema
python3 analyzer.py /var/log/auth.log

# Testar com o sample incluso
python3 analyzer.py samples/auth.log.sample

# Salvar relatório em arquivo
python3 analyzer.py /var/log/auth.log -o relatorio.txt

# Sem cores (útil para salvar em arquivo)
python3 analyzer.py /var/log/auth.log --no-color -o relatorio.txt
```

---

## Exemplo de output

```
============================================================
  LOG ANALYZER FOR SOC — RELATÓRIO
============================================================
  Arquivo : samples/auth.log.sample
  Data    : 2025-06-10 15:44:02
  Eventos : 27 linhas processadas
============================================================

[RESUMO]
------------------------------------------------------------
  Falhas de autenticação  : 14
  Logins bem-sucedidos    : 3
  Logins root diretos     : 1
  Eventos sudo            : 2
  Logins fora de horário  : 2

[TOP 5 — IPs COM MAIS FALHAS]
------------------------------------------------------------
  192.168.1.200          8 falhas
  203.0.113.42           6 falhas

[ALERTAS — 5 encontrado(s)]
------------------------------------------------------------
  [CRÍTICO] Brute force SSH/login
            IP 192.168.1.200 — 8 falhas de autenticação
  [CRÍTICO] Brute force SSH/login
            IP 203.0.113.42 — 6 falhas de autenticação
  [ALTO] Login direto como root
         IP 45.33.32.156 — login root direto detectado
  [MÉDIO] Login fora do horário comercial
          Usuário backup de 172.16.0.99 às Jun  5 21:47:02
  [MÉDIO] Login fora do horário comercial
          Usuário root de 45.33.32.156 às Jun  5 23:58:10
```

---

## Estrutura

```
log-analyzer-soc/
├── analyzer.py              # Script principal
├── samples/
│   └── auth.log.sample      # Log de exemplo para testes
└── README.md
```

---

## Como testar no seu sistema

O `auth.log` real do Linux fica em `/var/log/auth.log`. Em sistemas mais recentes (Ubuntu 22+) pode estar em `/var/log/syslog` ou acessível via:

```bash
sudo python3 analyzer.py /var/log/auth.log
```

> Requer sudo para leitura do auth.log em produção.

---

## Contexto Blue Team

Esse tipo de ferramenta representa o trabalho diário de um analista SOC Tier 1: processar volume alto de eventos, priorizar o que requer atenção imediata e documentar os achados. Ferramentas comerciais como Splunk e Wazuh fazem o mesmo em escala — entender a lógica por baixo é o que diferencia quem opera de quem apenas clica.

---

## Tecnologias

- Python 3.8+ (sem dependências externas)
- Regex para parsing de logs
- Biblioteca padrão: `re`, `collections`, `argparse`, `datetime`

---

## Autor

**Joederson Neves** — Blue Team | SOC | Segurança da Informação  
[GitHub](https://github.com/JoedersonN) · [LinkedIn](https://linkedin.com/in/joederson-neves-araujo) · [TryHackMe](https://tryhackme.com/p/Joe.Sk)
