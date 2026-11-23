#!/usr/bin/env python3
"""
Проверка HTTP Basic-авторизации на корне домена (только для своих / авторизованных целей).

Для каждого хоста из файла:
  1. GET /  без авторизации
       - ответ не 401 или нет WWW-Authenticate: Basic  -> хост пропускается
  2. GET /  с заголовком Authorization: Basic <base64(user:pass)>
       для каждой пары из --creds (по умолчанию топ-10, см. DEFAULT_CREDS)
       - 200 OK -> MATCH, остальные пары не проверяются

Использование:
    python3 basic_auth_check.py -f alive_cloud_assets.txt -o basic_auth_matches.txt
    python3 basic_auth_check.py -f hosts.txt --creds admin:admin --creds admin:password \
        --json basic_auth_results.json --user-agent "EASM by appsec@fozzy.ua"

Строки без схемы считаются https://. Пути в строках игнорируются: проверяется только корень.
"""
import argparse
import base64
import concurrent.futures
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

DEFAULT_CREDS = [
    "admin:admin",
    "admin:password",
    "admin:",            # пустой пароль
    "admin:123456",
    "demo:demo",
    "test:test",
    "guest:guest",
    "root:root",
    "user:user",
    "root:toor",

    # общие и системные
    "administrator:",
    "Administrator:password",
    "Administrator:admin",
    "Administrator:123456",
    "ubuntu:ubuntu",
    "vagrant:vagrant",
    "kali:kali",
    "alpine:alpine",
    "centos:centos",
    "debian:debian",
    "support:support",
    "operator:operator",
    "manager:manager",
    "service:service",
    "sysadmin:sysadmin",
    "pi:raspberry",
    "admin:1234",
    "admin:12345",
    "admin:12345678",
    "admin:admin123",
    "admin:Admin@123",
    "admin:changeme",
    "admin:default",
    "admin:pass",
    "root:123",
    "root:123456",
    "root:password",
    "root:pass",
    "root:changeme",
    "root:alpine",

    # сетевое оборудование и роутеры
    "cisco:cisco",
    "enable:cisco",
    "ubnt:ubnt",
    "admin:1234",
    "admin:smcadmin",
    "admin:zelax",
    "Admin:admin",
    "root:admin",
    "root:vizxv",
    "root:xc3511",
    "root:888888",
    "root:xmhdipc",
    "root:default",
    "support:support",
    "user:user",
    "mikrotik:mikrotik",

    # базы данных и инфраструктура
    "postgres:postgres",
    "sa:",
    "sa:sa",
    "root:",
    "root:mysql",
    "oracle:oracle",
    "system:manager",
    "sys:change_on_install",
    "scott:tiger",
    "elastic:changeme",
    "elastic:elastic",
    "minioadmin:minioadmin",
    "rabbitmq:rabbitmq",
    "Admin:zabbix",
    "admin:zabbix",
    "grafana:admin",
    "influx:influx",
    "redis:",

    # серверы приложений и CI/CD
    "tomcat:tomcat",
    "admin:tomcat",
    "tomcat:s3cret",
    "manager:s3cret",
    "weblogic:weblogic",
    "weblogic:welcome1",
    "weblogic:Welcome1",
    "jboss:jboss",
    "admin:jboss",
    "jenkins:jenkins",
    "admin:admin",
    "gitlab:5iveL!fe",

    # панели управления, CMS и мониторинг
    "admin:nimda",
    "admin:qwerty",
    "admin:letmein",
    "admin:1111",
    "admin:0000",
    "nagiosadmin:nagios",
    "kibana_system:changeme",
    "cpanel:cpanel",
    "whm:whm",
    "plesk:plesk",
]
BASIC_CHALLENGE_RE = re.compile(r"(^|,)\s*basic(\s|$)", re.IGNORECASE)


@dataclass
class Result:
    base_url: str
    unauth_status: Optional[int] = None
    challenge: Optional[str] = None        # WWW-Authenticate с 401
    matched: bool = False
    creds: Optional[str] = None            # пара, которая дала 200
    status: Optional[int] = None
    body_size: Optional[int] = None
    content_type: Optional[str] = None
    curl_poc: Optional[str] = None
    error: Optional[str] = None


def root_of(line: str) -> Optional[str]:
    """'host/path' -> 'https://host' (схема добавляется, если её нет)."""
    raw = line.strip()
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname:
        return None
    return f"{p.scheme}://{p.netloc}"


def read_bases(path: str) -> list[str]:
    bases: list[str] = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            base = root_of(s)
            if base:
                bases.append(base)
    return list(dict.fromkeys(bases))  # дедуп с сохранением порядка


def check_host(base: str, creds: list[str], timeout: int, verify: bool,
               headers: dict) -> Result:
    res = Result(base_url=base)
    root = base + "/"

    # 1. без авторизации
    try:
        r = requests.get(root, headers=headers, timeout=timeout, verify=verify,
                         allow_redirects=False)
    except requests.RequestException as e:
        res.error = str(e)
        return res

    res.unauth_status = r.status_code
    challenge = r.headers.get("WWW-Authenticate", "")
    if r.status_code != 401 or not BASIC_CHALLENGE_RE.search(challenge):
        return res
    res.challenge = challenge

    # 2. пробуем креды по очереди, первый 200 — матч
    for pair in creds:
        token = base64.b64encode(pair.encode("utf-8")).decode("ascii")
        h = dict(headers)
        h["Authorization"] = f"Basic {token}"
        try:
            r2 = requests.get(root, headers=h, timeout=timeout, verify=verify,
                              allow_redirects=False)
        except requests.RequestException:
            continue
        if r2.status_code == 200:
            res.matched = True
            res.creds = pair
            res.status = 200
            res.body_size = len(r2.content)
            res.content_type = r2.headers.get("Content-Type", "").split(";")[0].strip().lower()
            res.curl_poc = f"curl -i -u '{pair}' '{root}'"
            break
    return res


def main():
    ap = argparse.ArgumentParser(description="Проверка Basic-авторизации (admin:admin) на корнях доменов")
    ap.add_argument("-f", "--file", required=True, help="Файл с хостами/URL (один на строку)")
    ap.add_argument("-o", "--output", default="basic_auth_matches.txt",
                    help="Файл с матчами (URL, пара, статус)")
    ap.add_argument("--json", metavar="FILE", help="Полный результат по всем хостам с Basic-challenge (JSON)")
    ap.add_argument("--creds", action="append", metavar="USER:PASS",
                    help="Пара для проверки (можно несколько раз). По умолчанию топ-10 пар (см. DEFAULT_CREDS)")
    ap.add_argument("-w", "--workers", type=int, default=20, help="Параллельных хостов (default 20)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Таймаут запроса, сек (default 10)")
    ap.add_argument("--user-agent", default=None, help="User-Agent для запросов")
    ap.add_argument("--no-verify-ssl", action="store_true", help="Не проверять TLS-сертификаты")
    args = ap.parse_args()

    creds = args.creds or DEFAULT_CREDS
    for c in creds:
        if ":" not in c:
            sys.exit(f"--creds должен быть в формате USER:PASS, получено: {c!r}")

    bases = read_bases(args.file)
    if not bases:
        sys.exit("список хостов пуст")

    verify = not args.no_verify_ssl
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {"User-Agent": args.user_agent} if args.user_agent else {}

    print(f"[*] хостов: {len(bases)}, пар: {len(creds)} ({', '.join(creds)})")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda b: check_host(b, creds, args.timeout, verify, headers), bases))

    basic_hosts = [r for r in results if r.challenge]
    matches = [r for r in results if r.matched]

    with open(args.output, "w", encoding="utf-8") as f:
        for r in matches:
            f.write(f"{r.base_url}/  {r.creds}  {r.status}\n")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in basic_hosts], f, ensure_ascii=False, indent=2)

    print(f"[*] с Basic-challenge на /: {len(basic_hosts)}")
    print(f"[*] MATCH (200 с кредами): {len(matches)} -> {args.output}")
    for r in matches:
        print(f"  [MATCH] {r.base_url}/  creds={r.creds}  PoC: {r.curl_poc}")


if __name__ == "__main__":
    main()
