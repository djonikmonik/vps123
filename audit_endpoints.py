#!/usr/bin/env python3
"""
ETL-инструмент для аудита доступности сетевых эндпоинтов.

Назначение: парсинг, классификация, валидация и экспорт данных
о сетевых ресурсах из текстового файла data.txt.

Используется исключительно для аудита безопасности собственной
инфраструктуры и проверки конфигурации веб-серверов компании.
"""

import csv
import re
import sys
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import requests

# Подавляем предупреждения о самоподписанных сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Конфигурация ────────────────────────────────────────────────────────────

INPUT_FILE = "data.txt"
OUTPUT_FILE = "audit_results.csv"
REQUEST_TIMEOUT = 10          # секунд на один запрос
MAX_WORKERS = 20              # потоков для concurrent.futures
VALID_STATUS_CODES = {200, 403}  # коды, указывающие на активный эндпоинт
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ─── Паттерны классификации ──────────────────────────────────────────────────

CRITICAL_ADMIN_PATTERNS = [
    "/wp-admin", "/admin", "/login", "/signin", "phpmyadmin",
]

CLOUD_STORAGE_KEYWORDS = [
    "dropbox", "live.com", "google", "s3.amazonaws",
    "onedrive", "icloud", "box.com", "mega.nz",
]

# IPv4 прямые адреса (включая приватные диапазоны)
IP_ADDRESS_REGEX = re.compile(
    r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


# ─── Модель данных ───────────────────────────────────────────────────────────

@dataclass
class EndpointRecord:
    """Одна запись из data.txt после парсинга."""
    raw_line: str
    url: str = ""
    username: str = ""
    password: str = ""
    category: str = "General"
    status_code: Optional[int] = None
    status_text: str = ""
    error: str = ""


# ─── EXTRACT: Парсинг входного файла ────────────────────────────────────────

def parse_line(line: str) -> Optional[EndpointRecord]:
    """
    Разбирает строку формата  протокол://адрес:логин:пароль
    Поддерживает:
      - стандартные URL (https://, http://)
      - android:// схему
      - IP-адреса с нестандартными портами (192.168.1.1:8080)
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    record = EndpointRecord(raw_line=line)

    # Определяем схему (протокол)
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*://)", line)
    if not scheme_match:
        return None

    scheme = scheme_match.group(1)
    rest = line[len(scheme):]

    # Стратегия: разбиваем остаток справа, т.к. пароль — последний токен,
    # логин — предпоследний, всё остальное — адрес (может содержать ':' для порта).
    parts = rest.rsplit(":", 2)

    if len(parts) == 3:
        # адрес:логин:пароль
        record.url = scheme + parts[0]
        record.username = parts[1]
        record.password = parts[2]
    elif len(parts) == 2:
        # адрес:логин (пароль пуст)
        record.url = scheme + parts[0]
        record.username = parts[1]
    else:
        record.url = scheme + parts[0]

    # Для android:// — подменяем схему на https для проверки доступности
    if record.url.startswith("android://"):
        record.url = record.url.replace("android://", "https://", 1)

    return record


def extract(filepath: str) -> List[EndpointRecord]:
    """Читает файл и возвращает список распарсенных записей."""
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] Файл не найден: {filepath}")
        sys.exit(1)

    records: List[EndpointRecord] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            rec = parse_line(line)
            if rec is None:
                continue
            records.append(rec)

    print(f"[EXTRACT] Прочитано строк: {len(records)} из {filepath}")
    return records


# ─── TRANSFORM: Классификация ───────────────────────────────────────────────

def classify(record: EndpointRecord) -> str:
    """Определяет категорию эндпоинта."""
    url_lower = record.url.lower()

    # 1. Critical Admin
    for pattern in CRITICAL_ADMIN_PATTERNS:
        if pattern in url_lower:
            return "Critical Admin"

    # 2. Cloud / Storage
    for keyword in CLOUD_STORAGE_KEYWORDS:
        if keyword in url_lower:
            return "Cloud/Storage"

    # 3. Infrastructure (прямые IP-адреса)
    if IP_ADDRESS_REGEX.search(record.url):
        return "Infrastructure"

    return "General"


def transform(records: List[EndpointRecord]) -> List[EndpointRecord]:
    """Классифицирует все записи."""
    stats = {}
    for rec in records:
        rec.category = classify(rec)
        stats[rec.category] = stats.get(rec.category, 0) + 1

    print(f"[TRANSFORM] Классификация завершена:")
    for cat, count in sorted(stats.items()):
        print(f"  • {cat}: {count}")

    return records


# ─── VALIDATE: Проверка доступности (многопоточная) ──────────────────────────

def check_endpoint(record: EndpointRecord) -> EndpointRecord:
    """
    Отправляет GET-запрос к URL.
    Сохраняет статус-код; помечает ошибки при таймаутах / SSL-проблемах.
    verify=False — для самоподписанных сертификатов.
    """
    headers = {"User-Agent": USER_AGENT}

    try:
        resp = requests.get(
            record.url,
            timeout=REQUEST_TIMEOUT,
            verify=False,
            headers=headers,
            allow_redirects=True,
        )
        record.status_code = resp.status_code
        record.status_text = (
            "Active" if resp.status_code in VALID_STATUS_CODES else "Filtered"
        )

    except requests.exceptions.ConnectTimeout:
        record.status_text = "Timeout (connect)"
        record.error = "ConnectTimeout"

    except requests.exceptions.ReadTimeout:
        record.status_text = "Timeout (read)"
        record.error = "ReadTimeout"

    except requests.exceptions.SSLError as exc:
        record.status_text = "SSL Error"
        record.error = str(exc)[:120]

    except requests.exceptions.ConnectionError as exc:
        record.status_text = "Connection Error"
        record.error = str(exc)[:120]

    except requests.exceptions.RequestException as exc:
        record.status_text = "Request Error"
        record.error = str(exc)[:120]

    return record


def validate(records: List[EndpointRecord]) -> List[EndpointRecord]:
    """
    Многопоточная проверка доступности эндпоинтов.
    Использует concurrent.futures.ThreadPoolExecutor.
    Возвращает только записи с кодами 200 / 403 (активные эндпоинты).
    """
    total = len(records)
    completed = 0
    active_records: List[EndpointRecord] = []

    print(f"[VALIDATE] Запуск проверки {total} эндпоинтов ({MAX_WORKERS} потоков)...")
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_rec = {
            executor.submit(check_endpoint, rec): rec for rec in records
        }

        for future in as_completed(future_to_rec):
            completed += 1
            rec = future.result()

            status_display = (
                str(rec.status_code) if rec.status_code else rec.status_text
            )
            # Прогресс-бар
            print(
                f"\r  [{completed}/{total}] {rec.url[:60]:<60} → {status_display}",
                end="",
                flush=True,
            )

            # Фильтруем: оставляем только 200 и 403
            if rec.status_code in VALID_STATUS_CODES:
                active_records.append(rec)

    elapsed = time.time() - start_time
    print(f"\n[VALIDATE] Завершено за {elapsed:.1f}с. "
          f"Активных эндпоинтов: {len(active_records)}/{total}")

    return active_records


# ─── LOAD: Экспорт результатов в CSV ────────────────────────────────────────

def load(records: List[EndpointRecord], filepath: str) -> None:
    """Сохраняет отфильтрованные записи в CSV."""
    fieldnames = ["Source URL", "Type", "Status Code", "Credentials"]

    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for rec in records:
            writer.writerow({
                "Source URL": rec.url,
                "Type": rec.category,
                "Status Code": rec.status_code,
                "Credentials": f"{rec.username}:{rec.password}",
            })

    print(f"[LOAD] Результаты сохранены в {filepath} ({len(records)} записей)")


# ─── ОТЧЁТ: Полный дамп всех записей (включая отфильтрованные) ──────────────

def save_full_report(records: List[EndpointRecord], filepath: str) -> None:
    """Сохраняет полный отчёт со всеми записями (включая недоступные)."""
    fieldnames = [
        "Source URL", "Type", "Status Code", "Status", "Error", "Credentials",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for rec in records:
            writer.writerow({
                "Source URL": rec.url,
                "Type": rec.category,
                "Status Code": rec.status_code or "N/A",
                "Status": rec.status_text,
                "Error": rec.error,
                "Credentials": f"{rec.username}:{rec.password}",
            })

    print(f"[REPORT] Полный отчёт сохранён в {filepath} ({len(records)} записей)")


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  Endpoint Audit Tool — ETL Pipeline")
    print("  Аудит доступности сетевых эндпоинтов")
    print("=" * 70)
    print()

    # --- Extract ---
    records = extract(INPUT_FILE)
    if not records:
        print("[WARN] Нет данных для обработки.")
        sys.exit(0)

    # --- Transform ---
    records = transform(records)

    # --- Validate (Check Status) ---
    active_records = validate(records)

    # --- Load ---
    load(active_records, OUTPUT_FILE)

    # Дополнительно: полный отчёт со всеми записями
    save_full_report(records, "audit_full_report.csv")

    print()
    print("=" * 70)
    print(f"  Готово! Активные эндпоинты: {OUTPUT_FILE}")
    print(f"  Полный отчёт:               audit_full_report.csv")
    print("=" * 70)


if __name__ == "__main__":
    main()
