#!/usr/bin/env python3
"""
Отдельная проверка: 401 без авторизации -> 200 OK с кредами (только для своих / авторизованных целей).

Для каждого URL из файла:
  1. GET <url>  без авторизации
       - ответ не 401 -> пропуск
  2. GET <url>  с каждой парой из --creds (по умолчанию топ-10, см. DEFAULT_CREDS) как Basic Authorization
       - 200 OK -> MATCH: 401 -> 200 с кредами, остальные пары не проверяются

Не зависит от pipeline.py, запускается отдельно.

Использование:
    python3 check_401_to_200.py -f urls.txt
    python3 check_401_to_200.py -f urls.txt --creds admin:admin --creds root:toor \
        -o matches.txt --json results.json

Строки без схемы считаются https://. Путь из строки сохраняется (в отличие от basic_auth_check.py,
который проверяет только корень).
"""
import argparse
import base64
import concurrent.futures
import json
import sys
from dataclasses import asdict, dataclass
from typing import Optional

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
]


@dataclass
class Result:
    url: str
    unauth_status: Optional[int] = None
    matched: bool = False
    creds: Optional[str] = None
    status: Optional[int] = None
    body_size: Optional[int] = None
    content_type: Optional[str] = None
    curl_poc: Optional[str] = None
    error: Optional[str] = None


def normalize(line: str) -> Optional[str]:
    raw = line.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def read_urls(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            u = normalize(s)
            if u:
                urls.append(u)
    return list(dict.fromkeys(urls))


def check_url(url: str, creds: list[str], timeout: int, verify: bool, headers: dict) -> Result:
    res = Result(url=url)

    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=verify, allow_redirects=False)
    except requests.RequestException as e:
        res.error = str(e)
        return res

    res.unauth_status = r.status_code
    if r.status_code != 401:
        return res

    for pair in creds:
        token = base64.b64encode(pair.encode("utf-8")).decode("ascii")
        h = dict(headers)
        h["Authorization"] = f"Basic {token}"
        try:
            r2 = requests.get(url, headers=h, timeout=timeout, verify=verify, allow_redirects=False)
        except requests.RequestException:
            continue
        if r2.status_code == 200:
            res.matched = True
            res.creds = pair
            res.status = 200
            res.body_size = len(r2.content)
            res.content_type = r2.headers.get("Content-Type", "").split(";")[0].strip().lower()
            res.curl_poc = f"curl -i -u '{pair}' '{url}'"
            break
    return res


def main():
    ap = argparse.ArgumentParser(description="Проверка 401 -> 200 OK с Basic-кредами")
    ap.add_argument("-f", "--file", required=True, help="Файл с URL (один на строку)")
    ap.add_argument("-o", "--output", default="matches_401_200.txt", help="Файл с матчами")
    ap.add_argument("--json", metavar="FILE", help="Полный результат по всем URL с 401 (JSON)")
    ap.add_argument("--creds", action="append", metavar="USER:PASS",
                    help="Пара для проверки (можно несколько раз). По умолчанию топ-10 пар (см. DEFAULT_CREDS)")
    ap.add_argument("-w", "--workers", type=int, default=20, help="Параллельных запросов (default 20)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Таймаут, сек (default 10)")
    ap.add_argument("--user-agent", default=None, help="User-Agent")
    ap.add_argument("--no-verify-ssl", action="store_true", help="Не проверять TLS-сертификаты")
    args = ap.parse_args()

    creds = args.creds or DEFAULT_CREDS
    for c in creds:
        if ":" not in c:
            sys.exit(f"--creds должен быть USER:PASS, получено: {c!r}")

    urls = read_urls(args.file)
    if not urls:
        sys.exit("список URL пуст")

    verify = not args.no_verify_ssl
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {"User-Agent": args.user_agent} if args.user_agent else {}

    print(f"[*] URL: {len(urls)}, пар: {len(creds)} ({', '.join(creds)})")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda u: check_url(u, creds, args.timeout, verify, headers), urls))

    got_401 = [r for r in results if r.unauth_status == 401]
    matches = [r for r in results if r.matched]

    with open(args.output, "w", encoding="utf-8") as f:
        for r in matches:
            f.write(f"{r.url}  {r.creds}  {r.status}\n")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in got_401], f, ensure_ascii=False, indent=2)

    print(f"[*] ответили 401 без авторизации: {len(got_401)}")
    print(f"[*] MATCH 401 -> 200 OK: {len(matches)} -> {args.output}")
    for r in matches:
        print(f"  [MATCH] {r.url}  creds={r.creds}  PoC: {r.curl_poc}")


if __name__ == "__main__":
    main()
