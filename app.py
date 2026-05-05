# -*- coding: utf-8 -*-
"""
VLESS Aggregator & Checker
==========================
Десктопное приложение на Python (customtkinter) для:
  * автоматического сбора VLESS-прокси из публичных подписок
    (V2rayCollector / TVC / TGParse и т.п.) и из Telegram-каналов
    (опционально, через Telethon),
  * многопоточной проверки работоспособности через локальный Xray-core
    (SOCKS5 inbound + HTTP-запрос на cp.cloudflare.com / generate_204),
  * удобного управления списком в тёмном GUI: фильтры, сортировка,
    экспорт рабочих ссылок, ручной импорт из буфера обмена / файла.

Запуск:
    pip install -r requirements.txt
    python app.py

Все настройки хранятся в файлах settings.json и sources.json рядом
с приложением. Временные конфиги Xray складываются в temp_xray_configs/.

Кроссплатформенно: Windows / macOS / Linux. На Linux/macOS GUI требует
Tk (обычно идёт в комплекте с Python).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import ipaddress
import json
import os
import platform
import queue
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import traceback
import urllib.parse
import uuid as uuid_lib
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field, asdict
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Iterable

# ---------- Внешние зависимости (см. requirements.txt) ----------
try:
    import customtkinter as ctk  # noqa: F401
except ImportError as exc:  # pragma: no cover - зависит от окружения
    print("Не найден customtkinter. Установите: pip install customtkinter", file=sys.stderr)
    raise

try:
    import requests
except ImportError as exc:  # pragma: no cover
    print("Не найден requests. Установите: pip install requests", file=sys.stderr)
    raise

# dnspython используется для AAAA-резолвинга (фильтр «только IPv6»).
try:
    import dns.resolver  # type: ignore
    HAS_DNS = True
except Exception:  # pragma: no cover
    HAS_DNS = False

# Telethon — опционально, только если пользователь включит Telegram-скрапинг.
try:
    from telethon.sync import TelegramClient  # type: ignore  # noqa: F401
    HAS_TELETHON = True
except Exception:  # pragma: no cover
    HAS_TELETHON = False


# =============================================================================
#                              КОНСТАНТЫ И ПУТИ
# =============================================================================

APP_NAME = "VLESS Aggregator & Checker"
APP_VERSION = "1.0.0"

# Папка приложения (рядом с app.py); если запускается из site-packages — берём CWD.
APP_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
SETTINGS_PATH = os.path.join(APP_DIR, "settings.json")
SOURCES_PATH = os.path.join(APP_DIR, "sources.json")
TEMP_DIR = os.path.join(APP_DIR, "temp_xray_configs")
EXPORT_DEFAULT = os.path.join(APP_DIR, "working_vless.txt")

# Подписки по умолчанию — широкий набор активных публичных коллекторов.
# Каждая ссылка проверена на актуальность и количество vless-конфигов.
# Пользователь может добавлять/удалять их в настройках.
DEFAULT_SOURCES: list[str] = [
    # Большие сводные подписки (тысячи конфигов).
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/vless",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/vless",
    # Средние коллекторы.
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/main/speed.txt",
    # Меньшие, но часто живые подборки — добавляют разнообразия источников.
    "https://raw.githubusercontent.com/Roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
]

# Карта миграций: старые URL, которые больше не отвечают (404 / переименование
# репозитория / переезд файла) → новый адрес или None, если замены нет.
# Применяется при загрузке sources.json, чтобы у пользователей со старым
# конфигом сломанные ссылки автоматически заменялись на рабочие.
SOURCE_MIGRATIONS: dict[str, str | None] = {
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless":
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/Mix/mix.txt":
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Vless.txt":
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    # Файл удалён из репозитория, в нём остались только per-source списки.
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/v2rayfree.txt": None,
    # All_Configs_Sub.txt — те же конфиги, что и в Splitted-By-Protocol/vless.txt
    # плюс мусор других протоколов; заменяем на vless-конкретный путь, чтобы
    # экономить трафик и время AAAA-резолвинга.
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt":
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
}

DEFAULT_TG_CHANNELS: list[str] = [
    "v2rayng_proxy",
    "v2line",
    "MsV2ray",
    "v2rayng_v",
    "ConfigsHub",
]

DEFAULT_SETTINGS: dict[str, Any] = {
    "xray_path": "",                  # путь к бинарнику xray (если пусто — ищем в PATH)
    # Таймаут одной HTTP-проверки. 8 сек оказалось мало: VLESS+CDN+TLS
    # handshake часто не успевает уложиться, особенно через медленный
    # IPv6 path. 12 сек даёт большинству живых нод шанс ответить.
    "timeout_sec": 12,
    # Параллельность чека. 20 одновременно стартующих xray-инстансов на
    # обычной машине — гонка за ресурсами и фолс-фейлы по таймауту;
    # 8 — компромисс между скоростью и стабильностью.
    "threads": 8,
    "test_url": "http://cp.cloudflare.com/",
    "auto_refresh_min": 0,             # 0 = выключено, иначе минут между авто-обновлениями
    "ipv6_only": False,
    "telegram": {
        "enabled": False,
        "api_id": "",
        "api_hash": "",
        "channels": list(DEFAULT_TG_CHANNELS),
        "search_keywords": ["vless", "v2ray", "xray", "proxy"],
        "messages_limit": 200,
    },
}

# Регулярка для поиска vless-ссылок в произвольном тексте.
VLESS_RE = re.compile(r"vless://[^\s\"'<>]+", re.IGNORECASE)

# Цвета статусов (точки рядом с прокси).
STATUS_OK = "ok"          # ✅
STATUS_FAIL = "fail"      # ❌
STATUS_PENDING = "pending"  # ⏳
STATUS_CHECKING = "checking"  # ⌛

STATUS_DOTS: dict[str, str] = {
    STATUS_OK: "🟢",
    STATUS_FAIL: "🔴",
    STATUS_PENDING: "⚪",
    STATUS_CHECKING: "🟡",
}


# =============================================================================
#                         УТИЛИТЫ: ЛОГИРОВАНИЕ И КОНФИГ
# =============================================================================

def log(msg: str) -> None:
    """Простой лог в stdout; не используем стандартный logging, чтобы не
    усложнять. UI-логирование отдельно через `App.log_status`."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        log(f"Ошибка чтения {path}: {exc}")
        return default


def save_json(path: str, data: Any) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        log(f"Ошибка записи {path}: {exc}")


def deep_merge_defaults(user: dict, defaults: dict) -> dict:
    """Дополняет пользовательский конфиг отсутствующими ключами из defaults.
    Гарантирует, что после обновления приложения старые конфиги не падают."""
    merged: dict[str, Any] = dict(defaults)
    for key, value in user.items():
        if (
            key in defaults
            and isinstance(defaults[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge_defaults(value, defaults[key])
        else:
            merged[key] = value
    return merged


def load_settings() -> dict:
    raw = load_json(SETTINGS_PATH, {})
    return deep_merge_defaults(raw if isinstance(raw, dict) else {}, DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    save_json(SETTINGS_PATH, settings)


def _migrate_sources(sources: list[str]) -> tuple[list[str], bool]:
    """Заменяет известные сломанные URL на актуальные согласно SOURCE_MIGRATIONS.
    Возвращает (новый_список, было_ли_изменение)."""
    out: list[str] = []
    seen: set[str] = set()
    changed = False
    for src in sources:
        if src in SOURCE_MIGRATIONS:
            replacement = SOURCE_MIGRATIONS[src]
            changed = True
            if replacement is None:
                log(f"Источник {src} больше не существует — удалён из настроек")
                continue
            log(f"Источник {src} переехал → {replacement}")
            if replacement in seen:
                continue
            out.append(replacement)
            seen.add(replacement)
        else:
            if src in seen:
                continue
            out.append(src)
            seen.add(src)
    return out, changed


def load_sources() -> list[str]:
    data = load_json(SOURCES_PATH, None)
    if data is None:
        save_json(SOURCES_PATH, DEFAULT_SOURCES)
        return list(DEFAULT_SOURCES)
    if isinstance(data, list):
        sources = [str(x).strip() for x in data if str(x).strip()]
        sources, migrated = _migrate_sources(sources)
        if not sources:
            sources = list(DEFAULT_SOURCES)
            migrated = True
        if migrated:
            save_json(SOURCES_PATH, sources)
        return sources
    return list(DEFAULT_SOURCES)


def save_sources(sources: list[str]) -> None:
    save_json(SOURCES_PATH, sources)


# =============================================================================
#                        VLESS-ПАРСИНГ И НОРМАЛИЗАЦИЯ
# =============================================================================

@dataclass
class Proxy:
    """Распарсенный VLESS-прокси + рантайм-метаданные (статус, пинг, источник)."""
    url: str                       # исходная ссылка vless://...
    address: str                   # хост (домен или IP)
    port: int
    user_id: str                   # UUID
    name: str = ""                 # подпись (часть после #)
    network: str = "tcp"           # type=...
    security: str = "none"         # security=...
    sni: str = ""
    flow: str = ""
    fingerprint: str = ""
    public_key: str = ""           # pbk (для reality)
    short_id: str = ""             # sid (для reality)
    spider_x: str = ""             # spx
    ws_path: str = ""              # path
    ws_host: str = ""              # host
    grpc_service: str = ""         # serviceName
    header_type: str = ""          # tcp http header
    alpn: str = ""

    source: str = ""               # откуда добавлен
    status: str = STATUS_PENDING
    ping_ms: int = -1
    error: str = ""
    is_ipv6: bool | None = None    # известно ли уже, что хост — IPv6

    # ВНИМАНИЕ: id() не подходит для дедупликации между запусками;
    # ключом используем url. Этот атрибут — для UI Treeview.
    iid: str = field(default_factory=lambda: uuid_lib.uuid4().hex)

    def status_dot(self) -> str:
        return STATUS_DOTS.get(self.status, "⚪")

    def short_addr(self) -> str:
        addr = self.address
        if ":" in addr and not addr.startswith("["):
            # IPv6 — оборачиваем для красоты
            try:
                ipaddress.IPv6Address(addr)
                addr = f"[{addr}]"
            except Exception:
                pass
        return f"{addr}:{self.port}"


def _try_b64decode(text: str) -> str | None:
    """Возвращает декодированный текст, если `text` похож на base64 и
    содержит после декодирования хотя бы одну vless-ссылку.

    Корректный base64 — всегда ASCII, поэтому если в тексте есть не-ASCII
    символы (emoji, кириллица в заголовках подписки и т. п.) — это уже не
    base64-подписка, и пытаться декодировать не нужно. Без этой проверки
    `base64.b64decode` бросает `ValueError` на не-ASCII входе и роняет
    всю процедуру скрапинга.
    """
    stripped = text.strip()
    if len(stripped) < 24:
        return None
    if not stripped.isascii():
        return None
    # допускаем url-safe и обычный base64 без подложек
    cleaned = re.sub(r"\s+", "", stripped)
    padded = cleaned + "=" * (-len(cleaned) % 4)
    for variant in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            decoded = base64.b64decode(variant, validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if "vless://" in decoded.lower():
            return decoded
    return None


def parse_vless(url: str, source: str = "") -> Proxy | None:
    """Парсит одну vless-ссылку в объект Proxy. None — если ссылка битая."""
    url = url.strip()
    if not url.lower().startswith("vless://"):
        return None
    try:
        # urllib корректно разбирает userinfo@host:port, но иногда
        # в ссылках встречается "vless://uuid@[ipv6]:port" — это валидно.
        without_scheme = url[len("vless://"):]
        # Разделяем фрагмент (после #)
        if "#" in without_scheme:
            main_part, frag = without_scheme.split("#", 1)
            name = urllib.parse.unquote(frag).strip()
        else:
            main_part, name = without_scheme, ""
        # query-параметры
        if "?" in main_part:
            authority, query = main_part.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
        else:
            authority, params = main_part, {}

        if "@" not in authority:
            return None
        user_id, hostport = authority.split("@", 1)
        user_id = user_id.strip()
        if not user_id:
            return None

        # IPv6 в формате [::1]:port или просто host:port
        if hostport.startswith("["):
            # [ipv6]:port
            close = hostport.find("]")
            if close == -1:
                return None
            address = hostport[1:close]
            rest = hostport[close + 1:]
            if not rest.startswith(":"):
                return None
            port = int(rest[1:])
        else:
            if ":" not in hostport:
                return None
            address, port_s = hostport.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                return None

        if not address or port <= 0 or port > 65535:
            return None

        # Определим IPv6/IPv4 если можно сразу.
        is_ipv6: bool | None = None
        try:
            ip_obj = ipaddress.ip_address(address)
            is_ipv6 = ip_obj.version == 6
        except ValueError:
            is_ipv6 = None  # домен — выясним позже AAAA-запросом, если надо

        return Proxy(
            url=url,
            address=address,
            port=port,
            user_id=user_id,
            name=name or f"{address}:{port}",
            network=(params.get("type") or "tcp").lower(),
            security=(params.get("security") or "none").lower(),
            sni=params.get("sni", "") or params.get("peer", ""),
            flow=params.get("flow", ""),
            fingerprint=params.get("fp", ""),
            public_key=params.get("pbk", ""),
            short_id=params.get("sid", ""),
            spider_x=params.get("spx", ""),
            ws_path=urllib.parse.unquote(params.get("path", "") or ""),
            ws_host=params.get("host", ""),
            grpc_service=params.get("serviceName", ""),
            header_type=params.get("headerType", ""),
            alpn=params.get("alpn", ""),
            source=source,
            is_ipv6=is_ipv6,
        )
    except Exception as exc:  # pragma: no cover
        log(f"parse_vless failed for {url[:64]}…: {exc}")
        return None


def extract_vless_from_text(text: str, source: str = "") -> list[Proxy]:
    """Извлекает все vless-ссылки из произвольного куска текста.
    Учитывает, что подписки часто base64-кодированы целиком."""
    if not text:
        return []
    decoded = _try_b64decode(text)
    if decoded:
        text = decoded
    found = VLESS_RE.findall(text)
    proxies: list[Proxy] = []
    seen: set[str] = set()
    for raw in found:
        # Иногда регулярка ловит мусор в конце — отрежем "невалидные" хвосты.
        cleaned = raw.rstrip(" ,;\\\"'")
        if cleaned in seen:
            continue
        seen.add(cleaned)
        p = parse_vless(cleaned, source=source)
        if p is not None:
            proxies.append(p)
    return proxies


# =============================================================================
#                                 СКРАПЕРЫ
# =============================================================================

def scrape_url(url: str, timeout: float = 15.0) -> list[Proxy]:
    """Скачивает подписку и достаёт из неё все vless-ссылки.
    Любые ошибки сети/парсинга для одного источника не должны ронять
    общую процедуру обновления — поэтому всё, что упало, логируется и
    возвращается пустой список."""
    headers = {"User-Agent": f"{APP_NAME}/{APP_VERSION}"}
    try:
        resp = requests.get(url, timeout=timeout, headers=headers)
        resp.raise_for_status()
    except Exception as exc:
        log(f"Источник {url} недоступен: {exc}")
        return []
    try:
        return extract_vless_from_text(resp.text, source=url)
    except Exception as exc:
        log(f"Источник {url} не распарсился: {exc}")
        return []


def scrape_telegram(
    api_id: str,
    api_hash: str,
    channels: Iterable[str],
    search_keywords: Iterable[str],
    messages_limit: int = 200,
) -> list[Proxy]:
    """Собирает vless-ссылки из Telegram-каналов и из поиска по ключевым словам.
    Требует установленного telethon. Сессия хранится в `tg_session.session`
    рядом с приложением (создастся при первом запуске; нужна авторизация
    через телефон — Telethon запросит код/пароль в консоли)."""
    if not HAS_TELETHON:
        log("Telethon не установлен — Telegram-скрапинг недоступен")
        return []
    try:
        from telethon.sync import TelegramClient  # type: ignore
        from telethon.tl.functions.contacts import SearchRequest  # type: ignore
    except Exception as exc:  # pragma: no cover
        log(f"Telethon import error: {exc}")
        return []

    session_path = os.path.join(APP_DIR, "tg_session")
    proxies: list[Proxy] = []
    try:
        api_id_int = int(api_id)
    except Exception:
        log("api_id должен быть числом")
        return []

    try:
        with TelegramClient(session_path, api_id_int, api_hash) as client:
            # Целевые каналы — explicitly указанные пользователем
            visited: set[str] = set()
            for ch in channels:
                ch = ch.strip().lstrip("@").strip()
                if not ch or ch in visited:
                    continue
                visited.add(ch)
                try:
                    for msg in client.iter_messages(ch, limit=messages_limit):
                        if msg.message:
                            proxies.extend(extract_vless_from_text(msg.message, source=f"tg:@{ch}"))
                except Exception as exc:
                    log(f"TG канал @{ch} ошибка: {exc}")

            # Поиск новых каналов по ключевым словам
            for kw in search_keywords:
                kw = kw.strip()
                if not kw:
                    continue
                try:
                    res = client(SearchRequest(q=kw, limit=10))
                    for chat in getattr(res, "chats", []) or []:
                        username = getattr(chat, "username", None)
                        if not username or username in visited:
                            continue
                        visited.add(username)
                        try:
                            for msg in client.iter_messages(username, limit=min(50, messages_limit)):
                                if msg.message:
                                    proxies.extend(
                                        extract_vless_from_text(msg.message, source=f"tg:@{username}")
                                    )
                        except Exception as exc:
                            log(f"TG-поиск @{username}: {exc}")
                except Exception as exc:
                    log(f"TG-поиск по '{kw}': {exc}")
    except Exception as exc:
        log(f"Telegram-скрапинг упал: {exc}")
        traceback.print_exc()
    return proxies


def is_ipv6_host(address: str, dns_timeout: float = 3.0) -> bool:
    """True, если адрес — IPv6-литерал или домен резолвится в AAAA."""
    try:
        return ipaddress.ip_address(address).version == 6
    except ValueError:
        pass
    if not HAS_DNS:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = dns_timeout
        resolver.timeout = dns_timeout
        answers = resolver.resolve(address, "AAAA")
        return len(list(answers)) > 0
    except Exception:
        return False


# =============================================================================
#                          XRAY: ЗАПУСК И ПРОВЕРКА
# =============================================================================

def find_free_port() -> int:
    """Находит свободный TCP-порт на localhost — каждому проксированию
    нужен уникальный SOCKS5-инбаунд, чтобы не конфликтовать с соседними."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def discover_xray(custom_path: str = "") -> str | None:
    """Возвращает путь к бинарнику Xray. Сначала проверяем явный путь
    из настроек, потом PATH, потом стандартные системные локации."""
    candidates: list[str] = []
    if custom_path:
        candidates.append(custom_path)
    name = "xray.exe" if platform.system().lower().startswith("win") else "xray"
    in_path = shutil.which(name)
    if in_path:
        candidates.append(in_path)
    # Распространённые установки
    if platform.system().lower().startswith("win"):
        candidates += [
            r"C:\\Program Files\\Xray\\xray.exe",
            r"C:\\xray\\xray.exe",
        ]
    else:
        candidates += [
            "/usr/local/bin/xray",
            "/usr/bin/xray",
            "/opt/homebrew/bin/xray",
            os.path.expanduser("~/xray/xray"),
        ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK if not name.endswith(".exe") else os.R_OK):
            return c
    return None


def build_xray_config(proxy: Proxy, local_port: int) -> dict:
    """Строит конфиг Xray для одного VLESS-прокси с локальным SOCKS5
    инбаундом. Поддерживает tcp / ws / grpc и tls / reality / none."""
    stream_settings: dict[str, Any] = {
        "network": proxy.network or "tcp",
    }

    sec = (proxy.security or "none").lower()
    if sec in ("tls", "reality", "xtls"):
        stream_settings["security"] = sec
    else:
        stream_settings["security"] = "none"

    if stream_settings["security"] == "tls":
        tls = {
            "serverName": proxy.sni or proxy.ws_host or proxy.address,
            "allowInsecure": False,
        }
        if proxy.fingerprint:
            tls["fingerprint"] = proxy.fingerprint
        if proxy.alpn:
            tls["alpn"] = [a for a in proxy.alpn.split(",") if a]
        stream_settings["tlsSettings"] = tls
    elif stream_settings["security"] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": proxy.sni or proxy.address,
            "fingerprint": proxy.fingerprint or "chrome",
            "publicKey": proxy.public_key,
            "shortId": proxy.short_id,
            "spiderX": proxy.spider_x or "/",
        }

    network = (proxy.network or "tcp").lower()
    if network == "ws":
        stream_settings["wsSettings"] = {
            "path": proxy.ws_path or "/",
            "headers": ({"Host": proxy.ws_host} if proxy.ws_host else {}),
        }
    elif network == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": proxy.grpc_service or "",
            "multiMode": False,
        }
    elif network == "tcp" and proxy.header_type == "http":
        stream_settings["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "version": "1.1",
                    "method": "GET",
                    "path": [proxy.ws_path or "/"],
                    "headers": ({"Host": [proxy.ws_host]} if proxy.ws_host else {}),
                },
            }
        }
    elif network == "h2":
        stream_settings["httpSettings"] = {
            "host": [proxy.ws_host] if proxy.ws_host else [],
            "path": proxy.ws_path or "/",
        }

    user: dict[str, Any] = {
        "id": proxy.user_id,
        "encryption": "none",
    }
    if proxy.flow and stream_settings["security"] in ("tls", "reality", "xtls"):
        user["flow"] = proxy.flow

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": local_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": proxy.address,
                            "port": proxy.port,
                            "users": [user],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
    }


@dataclass
class CheckResult:
    ok: bool
    ping_ms: int
    error: str = ""


def _wait_socks_ready(port: int, timeout: float) -> bool:
    """Ждёт пока Xray поднимет SOCKS5 на указанном порту."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _tcp_reachable(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Быстрый TCP-предчек: пытается открыть TCP-соединение к (host, port).
    Возвращает (reachable, error_category). Категории — короткие (`tcp: …`,
    `dns: …`), их позже можно агрегировать в статус-бар после проверки.

    Идея: подавляющее большинство публичных VLESS-нод мертвы. Запускать
    xray на каждой — медленно (2-3 сек на старт + JSON + socks). А TCP
    connect занимает максимум `timeout` сек и параллелится без проблем,
    так что 80-95% дохлых нод можно отсеять быстро, оставив xray-чек
    только живым.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except socket.gaierror:
        return False, "dns: не резолвится"
    except (TimeoutError, socket.timeout):
        return False, "tcp: таймаут"
    except ConnectionRefusedError:
        return False, "tcp: connection refused"
    except OSError as e:
        msg = str(e).lower()
        if "unreachable" in msg or "no route" in msg:
            return False, "tcp: unreachable"
        return False, f"tcp: errno {e.errno}" if e.errno else "tcp: error"


def check_proxy(
    proxy: Proxy,
    xray_path: str,
    timeout: float,
    test_url: str,
    cancel_event: threading.Event,
) -> CheckResult:
    """Поднимает Xray для конкретной прокси и делает HTTP-запрос через
    локальный SOCKS5. Возвращает CheckResult(ok, ping_ms, error).
    Ошибки разнесены по категориям (`tls:`, `http:`, `xray:`, …),
    чтобы в статус-баре после проверки можно было показать пользователю,
    что именно фейлит. TCP-достижимость проверяется заранее на стадии 1
    в `_start_checks`, сюда долетают только живые на TCP-уровне ноды."""
    if cancel_event.is_set():
        return CheckResult(False, -1, "отменено")

    os.makedirs(TEMP_DIR, exist_ok=True)
    local_port = find_free_port()
    config = build_xray_config(proxy, local_port)
    tmp_name = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    cfg_path = os.path.join(TEMP_DIR, f"{tmp_name}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False)

    creation_flags = 0
    if platform.system().lower().startswith("win"):
        # Скрываем окно консоли xray на Windows.
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            [xray_path, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=creation_flags,
        )

        # xray обычно поднимает socks за 100-500мс, но на медленных Windows
        # с антивирусом может стартовать до 3-4 сек. Не зависим от
        # пользовательского timeout — отдельный фиксированный бюджет.
        if not _wait_socks_ready(local_port, 5.0):
            return CheckResult(False, -1, "xray: не запустил socks")

        if cancel_event.is_set():
            return CheckResult(False, -1, "отменено")

        socks_url = f"socks5h://127.0.0.1:{local_port}"
        proxies_dict = {"http": socks_url, "https": socks_url}
        start = time.perf_counter()
        try:
            r = requests.get(
                test_url,
                proxies=proxies_dict,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"},
            )
        except requests.exceptions.SSLError:
            return CheckResult(False, -1, "tls: handshake fail")
        except requests.exceptions.ConnectTimeout:
            return CheckResult(False, -1, "http: connect timeout")
        except requests.exceptions.ReadTimeout:
            return CheckResult(False, -1, "http: read timeout")
        except requests.exceptions.ProxyError as exc:
            # ProxyError обычно значит, что xray поднялся, но прокси-нода
            # отвалилась после установки socks (TLS/handshake внутри xray).
            return CheckResult(False, -1, "tunnel: closed")
        except requests.exceptions.RequestException as exc:
            return CheckResult(False, -1, f"http: {exc.__class__.__name__}")
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        # Принимаем 2xx и 3xx (generate_204 / cp.cloudflare.com и редиректы).
        if 200 <= r.status_code < 400:
            return CheckResult(True, elapsed_ms)
        return CheckResult(False, elapsed_ms, f"http: {r.status_code}")
    except FileNotFoundError:
        return CheckResult(False, -1, "xray: бинарник не найден")
    except Exception as exc:
        return CheckResult(False, -1, f"err: {exc.__class__.__name__}")
    finally:
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        with contextlib.suppress(Exception):
            os.remove(cfg_path)


# =============================================================================
#                                     UI
# =============================================================================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class SettingsDialog(ctk.CTkToplevel):
    """Окно настроек: Xray, проверка, Telegram, источники."""

    def __init__(self, master: "App", settings: dict, sources: list[str]):
        super().__init__(master)
        self.title("⚙️ Настройки")
        self.geometry("720x640")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.app = master
        self.settings = json.loads(json.dumps(settings))  # deep copy
        self.sources = list(sources)

        tabs = ctk.CTkTabview(self, width=700, height=560)
        tabs.pack(padx=12, pady=12, fill="both", expand=True)
        tab_general = tabs.add("Общее")
        tab_sources = tabs.add("Источники")
        tab_tg = tabs.add("Telegram")

        # ---------- Вкладка «Общее» ----------
        row = 0
        ctk.CTkLabel(tab_general, text="Путь к Xray:").grid(row=row, column=0, sticky="w", padx=10, pady=8)
        self.xray_var = tk.StringVar(value=self.settings["xray_path"])
        ctk.CTkEntry(tab_general, textvariable=self.xray_var, width=360).grid(row=row, column=1, padx=4, pady=8)
        ctk.CTkButton(tab_general, text="Обзор…", width=100, command=self._browse_xray).grid(row=row, column=2, padx=4)
        ctk.CTkButton(tab_general, text="Авто-поиск", width=100, command=self._auto_xray).grid(row=row, column=3, padx=4)

        row += 1
        ctk.CTkLabel(tab_general, text="Таймаут проверки (сек):").grid(row=row, column=0, sticky="w", padx=10, pady=8)
        self.timeout_var = tk.IntVar(value=int(self.settings["timeout_sec"]))
        ctk.CTkEntry(tab_general, textvariable=self.timeout_var, width=80).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        ctk.CTkLabel(tab_general, text="Потоков:").grid(row=row, column=0, sticky="w", padx=10, pady=8)
        self.threads_var = tk.IntVar(value=int(self.settings["threads"]))
        ctk.CTkEntry(tab_general, textvariable=self.threads_var, width=80).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        ctk.CTkLabel(tab_general, text="URL для проверки:").grid(row=row, column=0, sticky="w", padx=10, pady=8)
        self.test_url_var = tk.StringVar(value=self.settings["test_url"])
        ctk.CTkComboBox(
            tab_general,
            variable=self.test_url_var,
            values=[
                "http://cp.cloudflare.com/",
                "http://www.gstatic.com/generate_204",
                "http://detectportal.firefox.com/success.txt",
            ],
            width=360,
        ).grid(row=row, column=1, columnspan=2, sticky="w", padx=4)

        row += 1
        ctk.CTkLabel(tab_general, text="Авто-обновление, мин (0=выкл):").grid(row=row, column=0, sticky="w", padx=10, pady=8)
        self.auto_var = tk.IntVar(value=int(self.settings.get("auto_refresh_min", 0)))
        ctk.CTkEntry(tab_general, textvariable=self.auto_var, width=80).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        self.ipv6_var = tk.BooleanVar(value=bool(self.settings.get("ipv6_only", False)))
        ctk.CTkCheckBox(tab_general, text="Только IPv6 (фильтр на этапе сбора)", variable=self.ipv6_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=8
        )

        # ---------- Вкладка «Источники» ----------
        ctk.CTkLabel(tab_sources, text="URL подписок (по одной на строку):").pack(anchor="w", padx=10, pady=(10, 4))
        self.sources_text = ctk.CTkTextbox(tab_sources, width=660, height=380)
        self.sources_text.pack(padx=10, pady=4)
        self.sources_text.insert("1.0", "\n".join(self.sources))
        ctk.CTkLabel(
            tab_sources,
            text="Поддерживаются ссылки на raw-подписки (plain text или base64).",
            text_color="#888888",
        ).pack(anchor="w", padx=10)

        # ---------- Вкладка «Telegram» ----------
        tg = self.settings["telegram"]
        ctk.CTkLabel(tab_tg, text=("Telethon: " + ("установлен ✅" if HAS_TELETHON else "не установлен ⚠️"))).pack(
            anchor="w", padx=10, pady=(10, 4)
        )
        if not HAS_TELETHON:
            ctk.CTkLabel(
                tab_tg,
                text="Установите: pip install telethon",
                text_color="#ffaa55",
            ).pack(anchor="w", padx=10)
        self.tg_enabled_var = tk.BooleanVar(value=bool(tg.get("enabled")))
        ctk.CTkCheckBox(tab_tg, text="Включить сбор из Telegram", variable=self.tg_enabled_var).pack(
            anchor="w", padx=10, pady=(8, 4)
        )

        f = ctk.CTkFrame(tab_tg)
        f.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(f, text="api_id:").grid(row=0, column=0, padx=4, pady=4, sticky="w")
        self.tg_api_id_var = tk.StringVar(value=str(tg.get("api_id", "")))
        ctk.CTkEntry(f, textvariable=self.tg_api_id_var, width=200).grid(row=0, column=1, padx=4, pady=4)
        ctk.CTkLabel(f, text="api_hash:").grid(row=0, column=2, padx=4, pady=4, sticky="w")
        self.tg_api_hash_var = tk.StringVar(value=str(tg.get("api_hash", "")))
        ctk.CTkEntry(f, textvariable=self.tg_api_hash_var, width=260, show="•").grid(row=0, column=3, padx=4, pady=4)

        ctk.CTkLabel(tab_tg, text="Каналы (через запятую или с новой строки, без @):").pack(
            anchor="w", padx=10, pady=(10, 2)
        )
        self.tg_channels = ctk.CTkTextbox(tab_tg, width=660, height=120)
        self.tg_channels.pack(padx=10, pady=4)
        self.tg_channels.insert("1.0", "\n".join(tg.get("channels", [])))

        ctk.CTkLabel(tab_tg, text="Поисковые ключевые слова:").pack(anchor="w", padx=10, pady=(10, 2))
        self.tg_keywords = ctk.CTkEntry(tab_tg, width=660)
        self.tg_keywords.pack(padx=10, pady=4)
        self.tg_keywords.insert(0, ", ".join(tg.get("search_keywords", [])))

        ctk.CTkLabel(tab_tg, text="Сообщений на канал:").pack(anchor="w", padx=10, pady=(10, 2))
        self.tg_msgs_var = tk.IntVar(value=int(tg.get("messages_limit", 200)))
        ctk.CTkEntry(tab_tg, textvariable=self.tg_msgs_var, width=120).pack(anchor="w", padx=10, pady=4)

        ctk.CTkLabel(
            tab_tg,
            text="api_id и api_hash получаются на https://my.telegram.org → API development tools.",
            text_color="#888888",
            wraplength=660,
            justify="left",
        ).pack(anchor="w", padx=10, pady=(10, 4))

        # ---------- Кнопки сохранения ----------
        btns = ctk.CTkFrame(self)
        btns.pack(fill="x", padx=12, pady=8)
        ctk.CTkButton(btns, text="Сохранить", command=self._save).pack(side="right", padx=4)
        ctk.CTkButton(btns, text="Отмена", fg_color="#444", command=self.destroy).pack(side="right", padx=4)

    def _browse_xray(self) -> None:
        path = filedialog.askopenfilename(title="Выберите xray", parent=self)
        if path:
            self.xray_var.set(path)

    def _auto_xray(self) -> None:
        found = discover_xray("")
        if found:
            self.xray_var.set(found)
            messagebox.showinfo(APP_NAME, f"Найдено: {found}", parent=self)
        else:
            messagebox.showwarning(
                APP_NAME,
                "Xray не найден. Скачайте релиз с https://github.com/XTLS/Xray-core/releases "
                "и укажите путь вручную.",
                parent=self,
            )

    def _save(self) -> None:
        try:
            self.settings["xray_path"] = self.xray_var.get().strip()
            self.settings["timeout_sec"] = max(1, int(self.timeout_var.get()))
            self.settings["threads"] = max(1, min(200, int(self.threads_var.get())))
            self.settings["test_url"] = self.test_url_var.get().strip() or DEFAULT_SETTINGS["test_url"]
            self.settings["auto_refresh_min"] = max(0, int(self.auto_var.get()))
            self.settings["ipv6_only"] = bool(self.ipv6_var.get())

            tg = self.settings["telegram"]
            tg["enabled"] = bool(self.tg_enabled_var.get())
            tg["api_id"] = self.tg_api_id_var.get().strip()
            tg["api_hash"] = self.tg_api_hash_var.get().strip()
            tg["messages_limit"] = max(10, int(self.tg_msgs_var.get()))
            tg["channels"] = [
                x.strip().lstrip("@")
                for x in re.split(r"[,\n\r]+", self.tg_channels.get("1.0", "end").strip())
                if x.strip()
            ]
            tg["search_keywords"] = [
                x.strip()
                for x in re.split(r"[,\n\r]+", self.tg_keywords.get().strip())
                if x.strip()
            ]

            new_sources = [
                s.strip()
                for s in self.sources_text.get("1.0", "end").splitlines()
                if s.strip() and s.strip().lower().startswith(("http://", "https://"))
            ]
            self.sources = new_sources

            self.app.apply_settings(self.settings, self.sources)
            self.destroy()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Не получилось сохранить: {exc}", parent=self)


class App(ctk.CTk):
    """Главное окно: панель кнопок + таблица + статус-бар."""

    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.geometry("1280x780")
        self.minsize(1000, 640)

        # Состояние
        self.settings: dict = load_settings()
        self.sources: list[str] = load_sources()

        # url -> Proxy. Используем url как первичный ключ для дедупа.
        self.proxies: dict[str, Proxy] = {}
        # iid -> url  (iid — внутренний идентификатор Treeview)
        self.iid_to_url: dict[str, str] = {}

        self.cancel_event = threading.Event()
        self.executor: ThreadPoolExecutor | None = None
        self.running_futures: list[Future] = []
        self.is_scraping = False
        self.is_checking = False
        # Очередь UI-обновлений из фоновых потоков
        self.ui_queue: queue.Queue = queue.Queue()
        # Авто-обновление
        self._auto_after_id: str | None = None

        self._build_ui()
        self._schedule_ui_pump()
        self._schedule_auto_refresh()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------- Левая панель ----------
        side = ctk.CTkFrame(self, width=240, corner_radius=12)
        side.grid(row=0, column=0, sticky="nsw", padx=10, pady=10)
        side.grid_propagate(False)

        ctk.CTkLabel(
            side, text=f"🛡 {APP_NAME}", font=("", 16, "bold")
        ).pack(padx=12, pady=(14, 4), anchor="w")
        ctk.CTkLabel(side, text=f"v{APP_VERSION}", text_color="#888").pack(padx=12, anchor="w")

        ctk.CTkLabel(side, text=" ", height=8).pack()

        self.btn_refresh = ctk.CTkButton(
            side, text="🔄  Обновить из источников", command=self.action_refresh, height=40
        )
        self.btn_refresh.pack(fill="x", padx=12, pady=4)

        self.btn_check = ctk.CTkButton(
            side, text="✅  Проверить всё", command=self.action_check_all, height=40, fg_color="#1f7a3a", hover_color="#175c2c"
        )
        self.btn_check.pack(fill="x", padx=12, pady=4)

        self.btn_stop = ctk.CTkButton(
            side, text="⏹  Стоп", command=self.action_stop, height=36, fg_color="#7a1f1f", hover_color="#5c1717"
        )
        self.btn_stop.pack(fill="x", padx=12, pady=4)

        self.btn_clear = ctk.CTkButton(
            side, text="🗑  Очистить список", command=self.action_clear, height=36, fg_color="#444"
        )
        self.btn_clear.pack(fill="x", padx=12, pady=4)

        ctk.CTkLabel(side, text=" ", height=8).pack()

        self.ipv6_var = tk.BooleanVar(value=bool(self.settings.get("ipv6_only", False)))
        ctk.CTkCheckBox(side, text="Только IPv6", variable=self.ipv6_var, command=self._on_ipv6_toggle).pack(
            anchor="w", padx=14, pady=4
        )

        ctk.CTkLabel(side, text="Поиск по таблице:").pack(anchor="w", padx=14, pady=(10, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._refresh_table())
        ctk.CTkEntry(side, textvariable=self.filter_var, placeholder_text="имя, адрес, …").pack(
            fill="x", padx=12, pady=4
        )

        ctk.CTkLabel(side, text="Показывать:").pack(anchor="w", padx=14, pady=(10, 2))
        self.show_var = tk.StringVar(value="all")
        for value, label in (("all", "Все"), ("ok", "Только рабочие"), ("fail", "Только нерабочие")):
            ctk.CTkRadioButton(
                side, text=label, value=value, variable=self.show_var, command=self._refresh_table
            ).pack(anchor="w", padx=18, pady=2)

        ctk.CTkLabel(side, text=" ", height=8).pack()
        ctk.CTkButton(side, text="📋  Импорт из буфера", command=self.action_paste, height=32, fg_color="#444").pack(
            fill="x", padx=12, pady=2
        )
        ctk.CTkButton(side, text="📂  Импорт из файла", command=self.action_import_file, height=32, fg_color="#444").pack(
            fill="x", padx=12, pady=2
        )
        ctk.CTkButton(
            side, text="📋  Копировать рабочие", command=self.action_copy_working, height=32
        ).pack(fill="x", padx=12, pady=(12, 2))
        ctk.CTkButton(
            side, text="💾  Сохранить рабочие", command=self.action_save_working, height=32
        ).pack(fill="x", padx=12, pady=2)

        ctk.CTkLabel(side, text=" ", height=12).pack()
        ctk.CTkButton(side, text="⚙  Настройки", command=self.action_settings, height=32, fg_color="#333").pack(
            fill="x", padx=12, pady=2
        )

        # ---------- Правая часть: таблица + статус ----------
        main = ctk.CTkFrame(self, corner_radius=12)
        main.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # Прогресс / фильтр-инфо сверху
        topbar = ctk.CTkFrame(main, fg_color="transparent")
        topbar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        topbar.grid_columnconfigure(1, weight=1)
        self.title_label = ctk.CTkLabel(topbar, text="📋 Список прокси", font=("", 14, "bold"))
        self.title_label.grid(row=0, column=0, sticky="w", padx=4)
        self.progress = ctk.CTkProgressBar(topbar, width=320)
        self.progress.set(0)
        self.progress.grid(row=0, column=1, sticky="e", padx=4)

        # Treeview (стилизуем под тёмную тему)
        style = ttk.Style()
        with contextlib.suppress(Exception):
            style.theme_use("clam")
        bg = "#1e1f22"
        fg = "#e6e6e6"
        sel = "#264f78"
        style.configure(
            "Treeview",
            background=bg,
            foreground=fg,
            fieldbackground=bg,
            rowheight=26,
            bordercolor=bg,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#2a2c30",
            foreground="#cccccc",
            relief="flat",
            font=("", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", sel)], foreground=[("selected", "#ffffff")])

        table_wrap = ctk.CTkFrame(main, fg_color="transparent")
        table_wrap.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        table_wrap.grid_columnconfigure(0, weight=1)
        table_wrap.grid_rowconfigure(0, weight=1)

        columns = ("status", "name", "addr", "proto", "ping", "source")
        self.tree = ttk.Treeview(table_wrap, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("status", text="●")
        self.tree.heading("name", text="Имя")
        self.tree.heading("addr", text="Адрес:Порт")
        self.tree.heading("proto", text="Сеть / Sec / Flow")
        self.tree.heading("ping", text="Пинг / Ошибка")
        self.tree.heading("source", text="Источник")
        self.tree.column("status", width=44, anchor="center", stretch=False)
        self.tree.column("name", width=240)
        self.tree.column("addr", width=240)
        self.tree.column("proto", width=180, anchor="center")
        self.tree.column("ping", width=80, anchor="center", stretch=False)
        self.tree.column("source", width=300)

        vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        # Контекстное меню
        self.context_menu = tk.Menu(self.tree, tearoff=0, bg="#2a2c30", fg="#e6e6e6", activebackground="#264f78")
        self.context_menu.add_command(label="📋 Копировать ссылку", command=self._ctx_copy_url)
        self.context_menu.add_command(label="✅ Проверить выбранные", command=self._ctx_check_selected)
        self.context_menu.add_command(label="🗑 Удалить выбранные", command=self._ctx_delete_selected)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Button-2>", self._show_context_menu)  # macOS

        # Цветные теги для строк
        self.tree.tag_configure("ok", foreground="#7ee787")
        self.tree.tag_configure("fail", foreground="#ff7b72")
        self.tree.tag_configure("pending", foreground="#cccccc")
        self.tree.tag_configure("checking", foreground="#ffd166")

        # Статус-бар снизу
        statusbar = ctk.CTkFrame(main, height=40, corner_radius=8)
        statusbar.grid(row=2, column=0, sticky="ew", padx=8, pady=(4, 8))
        self.status_label = ctk.CTkLabel(
            statusbar,
            text="Готов. Нажмите «Обновить из источников», чтобы начать.",
            anchor="w",
        )
        self.status_label.pack(side="left", padx=10, pady=8, fill="x", expand=True)
        self.counter_label = ctk.CTkLabel(statusbar, text="Всего: 0 | Рабочих: 0 | Нерабочих: 0")
        self.counter_label.pack(side="right", padx=10)

    # ------------------------------------------------------------ Событийная очередь
    def _schedule_ui_pump(self) -> None:
        """Каждые ~80мс достаёт сообщения из очереди фоновых потоков и
        безопасно применяет их к UI."""
        try:
            while True:
                fn = self.ui_queue.get_nowait()
                try:
                    fn()
                except Exception as exc:
                    log(f"UI callback error: {exc}")
                    traceback.print_exc()
        except queue.Empty:
            pass
        self.after(80, self._schedule_ui_pump)

    def _post(self, fn: Callable[[], None]) -> None:
        self.ui_queue.put(fn)

    # ------------------------------------------------------------ Кнопки
    def action_settings(self) -> None:
        SettingsDialog(self, self.settings, self.sources)

    def apply_settings(self, settings: dict, sources: list[str]) -> None:
        self.settings = settings
        self.sources = sources
        save_settings(settings)
        save_sources(sources)
        # синхронизация с боковой галкой
        self.ipv6_var.set(bool(settings.get("ipv6_only", False)))
        self._schedule_auto_refresh()
        self.log_status("Настройки сохранены.")

    def _on_ipv6_toggle(self) -> None:
        self.settings["ipv6_only"] = bool(self.ipv6_var.get())
        save_settings(self.settings)
        self._refresh_table()

    def action_refresh(self) -> None:
        if self.is_scraping:
            self.log_status("Сбор уже выполняется…")
            return
        self.is_scraping = True
        self.cancel_event.clear()
        self.progress.set(0)
        self.log_status("Начинаю сбор из источников…")
        threading.Thread(target=self._scrape_worker, daemon=True).start()

    def action_check_all(self) -> None:
        if self.is_checking:
            self.log_status("Проверка уже идёт.")
            return
        proxies = list(self.proxies.values())
        if not proxies:
            self.log_status("Список пуст. Сначала обновите источники.")
            return
        xray = discover_xray(self.settings.get("xray_path", ""))
        if not xray:
            messagebox.showwarning(
                APP_NAME,
                "Не найден Xray-core.\n\n"
                "Скачайте релиз с https://github.com/XTLS/Xray-core/releases\n"
                "и укажите путь к бинарнику в настройках (⚙ Настройки).",
                parent=self,
            )
            return
        self.cancel_event.clear()
        self.is_checking = True
        self._start_checks(proxies, xray)

    def action_stop(self) -> None:
        if self.is_scraping or self.is_checking:
            self.log_status("Останавливаю…")
            self.cancel_event.set()
            if self.executor is not None:
                self.executor.shutdown(wait=False, cancel_futures=True)
        else:
            self.log_status("Нечего останавливать.")

    def action_clear(self) -> None:
        if self.is_checking or self.is_scraping:
            messagebox.showinfo(APP_NAME, "Сначала остановите текущую операцию.", parent=self)
            return
        if not messagebox.askyesno(APP_NAME, "Очистить список прокси?", parent=self):
            return
        self.proxies.clear()
        self.iid_to_url.clear()
        self.tree.delete(*self.tree.get_children())
        self._update_counter()
        self.log_status("Список очищен.")

    def action_paste(self) -> None:
        try:
            text = self.clipboard_get()
        except Exception:
            text = ""
        if not text.strip():
            self.log_status("Буфер обмена пуст.")
            return
        added = self._merge_proxies(extract_vless_from_text(text, source="clipboard"))
        self.log_status(f"Из буфера импортировано: {added} новых.")

    def action_import_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Импорт VLESS",
            filetypes=[("Текстовые файлы", "*.txt *.list *.cfg *.csv"), ("Все файлы", "*.*")],
            parent=self,
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Не удалось прочитать файл: {exc}", parent=self)
            return
        added = self._merge_proxies(extract_vless_from_text(text, source=os.path.basename(path)))
        self.log_status(f"Из файла импортировано: {added} новых.")

    def action_copy_working(self) -> None:
        working = [p.url for p in self.proxies.values() if p.status == STATUS_OK]
        if not working:
            self.log_status("Рабочих прокси нет.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(working))
        self.log_status(f"Скопировано {len(working)} рабочих ссылок в буфер.")

    def action_save_working(self) -> None:
        working = [p.url for p in self.proxies.values() if p.status == STATUS_OK]
        if not working:
            self.log_status("Рабочих прокси нет — нечего сохранять.")
            return
        path = filedialog.asksaveasfilename(
            title="Сохранить рабочие VLESS",
            defaultextension=".txt",
            initialfile="working_vless.txt",
            initialdir=APP_DIR,
            filetypes=[("Текстовый файл", "*.txt")],
            parent=self,
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(working))
            self.log_status(f"Сохранено {len(working)} ссылок в {path}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить: {exc}", parent=self)

    # ------------------------------------------------------------ Контекстное меню
    def _show_context_menu(self, event: tk.Event) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def _selected_proxies(self) -> list[Proxy]:
        items = self.tree.selection()
        out: list[Proxy] = []
        for iid in items:
            url = self.iid_to_url.get(iid)
            if url and url in self.proxies:
                out.append(self.proxies[url])
        return out

    def _ctx_copy_url(self) -> None:
        items = self._selected_proxies()
        if not items:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(p.url for p in items))
        self.log_status(f"Скопировано ссылок: {len(items)}")

    def _ctx_check_selected(self) -> None:
        items = self._selected_proxies()
        if not items:
            return
        if self.is_checking:
            self.log_status("Проверка уже идёт.")
            return
        xray = discover_xray(self.settings.get("xray_path", ""))
        if not xray:
            messagebox.showwarning(APP_NAME, "Сначала укажите путь к Xray в настройках.", parent=self)
            return
        self.cancel_event.clear()
        self.is_checking = True
        self._start_checks(items, xray)

    def _ctx_delete_selected(self) -> None:
        items = self._selected_proxies()
        if not items:
            return
        for p in items:
            self.proxies.pop(p.url, None)
        # перерисуем таблицу полностью — это надёжнее
        self.tree.delete(*self.tree.get_children())
        self.iid_to_url.clear()
        for p in self.proxies.values():
            self._insert_row(p)
        self._refresh_table()
        self._update_counter()
        self.log_status(f"Удалено: {len(items)}")

    # ------------------------------------------------------------ Скрапинг (фон)
    def _scrape_worker(self) -> None:
        """Фоновый поток: тянем все источники и Telegram параллельно,
        размечаем IPv6 (AAAA-резолвинг) и добавляем новые прокси в
        self.proxies через UI-очередь."""
        try:
            sources = list(self.sources)
            tg_cfg = self.settings.get("telegram", {})
            tg_enabled = bool(tg_cfg.get("enabled")) and HAS_TELETHON
            total_steps = len(sources) + (1 if tg_enabled else 0)
            done = 0
            done_lock = threading.Lock()

            def step(label: str) -> None:
                nonlocal done
                with done_lock:
                    done += 1
                    progress = done / max(1, total_steps)
                self._post(lambda p=progress: self.progress.set(p))
                self._post(lambda lbl=label: self.log_status(lbl))

            new_proxies: list[Proxy] = []
            new_lock = threading.Lock()

            def fetch_one(url: str) -> None:
                if self.cancel_event.is_set():
                    return
                fetched = scrape_url(url)
                with new_lock:
                    new_proxies.extend(fetched)
                step(f"Источник {url}: {len(fetched)} ссылок")

            self._post(lambda n=len(sources): self.log_status(
                f"Скачиваю {n} источников параллельно…"
            ))
            with ThreadPoolExecutor(max_workers=min(8, max(1, len(sources)))) as ex:
                list(ex.map(fetch_one, sources))

            if tg_enabled and not self.cancel_event.is_set():
                self._post(lambda: self.log_status("Telegram: подключаюсь…"))
                fetched = scrape_telegram(
                    api_id=str(tg_cfg.get("api_id", "")),
                    api_hash=str(tg_cfg.get("api_hash", "")),
                    channels=tg_cfg.get("channels", []),
                    search_keywords=tg_cfg.get("search_keywords", []),
                    messages_limit=int(tg_cfg.get("messages_limit", 200)),
                )
                with new_lock:
                    new_proxies.extend(fetched)
                step(f"Telegram: {len(fetched)} ссылок")

            # Размечаем IPv6 для всех прокси, у которых статус неизвестен.
            # Делаем это всегда (а не только при ipv6_only), чтобы:
            #   * сортировка таблицы могла поднять IPv6-узлы наверх;
            #   * при включении «Только IPv6» в UI ответ был мгновенным.
            # Резолвинг параллельный, чтобы тысячи AAAA-запросов не висели час.
            if new_proxies and not self.cancel_event.is_set():
                pending = [p for p in new_proxies if p.is_ipv6 is None]
                if pending:
                    self._post(lambda n=len(pending): self.log_status(
                        f"AAAA-резолвинг для приоритезации IPv6 ({n} хостов)…"
                    ))
                    seen: dict[str, bool] = {}

                    def resolve_one(p: Proxy) -> None:
                        if self.cancel_event.is_set():
                            return
                        addr = p.address
                        cached = seen.get(addr)
                        if cached is not None:
                            p.is_ipv6 = cached
                            return
                        try:
                            v6 = is_ipv6_host(addr)
                        except Exception:
                            v6 = False
                        seen[addr] = v6
                        p.is_ipv6 = v6

                    with ThreadPoolExecutor(max_workers=32) as ex:
                        list(ex.map(resolve_one, pending))

            # Жёсткий IPv6-фильтр (если пользователь включил «Только IPv6»).
            if self.settings.get("ipv6_only") and new_proxies and not self.cancel_event.is_set():
                new_proxies = [p for p in new_proxies if p.is_ipv6]

            # Применяем
            def commit() -> None:
                added = self._merge_proxies(new_proxies)
                # Полная перерисовка, чтобы IPv6-приоритет сразу применился.
                self._refresh_table()
                self.progress.set(1.0)
                v6 = sum(1 for p in self.proxies.values() if p.is_ipv6)
                self.log_status(
                    f"Готово. Добавлено {added} новых, всего: {len(self.proxies)} "
                    f"(IPv6: {v6})."
                )
                self.after(1500, lambda: self.progress.set(0))

            self._post(commit)
        except Exception as exc:
            self._post(lambda e=exc: self.log_status(f"Скрапинг упал: {e}"))
            traceback.print_exc()
        finally:
            self.is_scraping = False

    # ------------------------------------------------------------ Вставка в таблицу
    def _merge_proxies(self, items: Iterable[Proxy]) -> int:
        """Вставляет новые прокси (по URL — ключ дедупликации). Возвращает
        количество фактически новых."""
        added = 0
        for p in items:
            if not p:
                continue
            if p.url in self.proxies:
                # обновим только источник если нужно (склеиваем)
                existing = self.proxies[p.url]
                if p.source and p.source not in (existing.source or ""):
                    existing.source = (
                        f"{existing.source}; {p.source}" if existing.source else p.source
                    )
                continue
            self.proxies[p.url] = p
            added += 1
            self._insert_row(p)
        self._update_counter()
        return added

    @staticmethod
    def _ping_or_error(p: Proxy) -> str:
        """Что показать в колонке «Пинг / Ошибка»: миллисекунды для
        рабочих, краткую категорию ошибки для нерабочих, прочерк —
        для ещё не проверенных."""
        if p.ping_ms >= 0:
            return f"{p.ping_ms}"
        if p.status == STATUS_FAIL and p.error:
            return p.error
        return "—"

    def _insert_row(self, p: Proxy) -> None:
        if not self._proxy_visible(p):
            return
        proto = "/".join(filter(None, [p.network, p.security, p.flow])) or p.network
        ping_text = self._ping_or_error(p)
        self.tree.insert(
            "",
            "end",
            iid=p.iid,
            values=(
                p.status_dot(),
                p.name,
                p.short_addr(),
                proto,
                ping_text,
                p.source,
            ),
            tags=(p.status,),
        )
        self.iid_to_url[p.iid] = p.url

    def _update_row(self, p: Proxy) -> None:
        if not self.tree.exists(p.iid):
            self._insert_row(p)
            return
        if not self._proxy_visible(p):
            self.tree.delete(p.iid)
            self.iid_to_url.pop(p.iid, None)
            return
        proto = "/".join(filter(None, [p.network, p.security, p.flow])) or p.network
        ping_text = self._ping_or_error(p)
        self.tree.item(
            p.iid,
            values=(p.status_dot(), p.name, p.short_addr(), proto, ping_text, p.source),
            tags=(p.status,),
        )

    def _proxy_visible(self, p: Proxy) -> bool:
        # IPv6-фильтр уже применяется на этапе сбора, но если пользователь
        # включил его после — спрячем не-IPv6 в UI.
        if self.settings.get("ipv6_only"):
            if p.is_ipv6 is None:
                # Не блокируем UI ради DNS — попробуем только литерал
                with contextlib.suppress(ValueError):
                    p.is_ipv6 = ipaddress.ip_address(p.address).version == 6
            if not p.is_ipv6:
                return False
        show = self.show_var.get() if hasattr(self, "show_var") else "all"
        if show == "ok" and p.status != STATUS_OK:
            return False
        if show == "fail" and p.status != STATUS_FAIL:
            return False
        text = (self.filter_var.get() if hasattr(self, "filter_var") else "").strip().lower()
        if text:
            haystack = " ".join([p.name, p.address, str(p.port), p.source, p.network, p.security]).lower()
            if text not in haystack:
                return False
        return True

    def _refresh_table(self) -> None:
        # Полная перерисовка — простой и надёжный способ.
        self.tree.delete(*self.tree.get_children())
        self.iid_to_url.clear()
        # Сортировка: IPv6 наверху (приоритет), затем «рабочие → проверяющиеся
        # → ожидающие → нерабочие», затем по возрастанию пинга. Сортируем
        # стабильно (sorted) — порядок внутри одной группы остаётся как был.
        status_order = {STATUS_OK: 0, STATUS_CHECKING: 1, STATUS_PENDING: 2, STATUS_FAIL: 3}
        items = sorted(
            self.proxies.values(),
            key=lambda p: (
                0 if p.is_ipv6 else 1,
                status_order.get(p.status, 9),
                p.ping_ms if p.ping_ms >= 0 else 10**9,
            ),
        )
        for p in items:
            self._insert_row(p)
        self._update_counter()

    def _update_counter(self) -> None:
        total = len(self.proxies)
        ok = sum(1 for p in self.proxies.values() if p.status == STATUS_OK)
        fail = sum(1 for p in self.proxies.values() if p.status == STATUS_FAIL)
        self.counter_label.configure(
            text=f"Всего: {total} | Рабочих: {ok} | Нерабочих: {fail}"
        )

    def log_status(self, text: str) -> None:
        self.status_label.configure(text=text)
        log(text)

    # ------------------------------------------------------------ Проверка
    def _start_checks(self, proxies: list[Proxy], xray_path: str) -> None:
        """Двухстадийная проверка:
        1) быстрый параллельный TCP-предчек (64 потока) — отсекает дохлые
           хосты за секунды;
        2) полный xray-чек (`threads` потоков) только для тех, кто прошёл
           TCP. Так на 11k прокси экономится десятки минут.
        """
        timeout = float(self.settings.get("timeout_sec", 12))
        threads = int(self.settings.get("threads", 8))
        test_url = str(self.settings.get("test_url") or DEFAULT_SETTINGS["test_url"])
        total = len(proxies)
        done = {"n": 0}

        # Помечаем все как "checking"
        for p in proxies:
            p.status = STATUS_CHECKING
            p.error = ""
            self._post(lambda pp=p: self._update_row(pp))

        self.progress.set(0)

        # Стадия 1 крутится в отдельном фоновом потоке, чтобы UI оставался
        # отзывчивым (а потом в нём же запускается стадия 2 через executor).
        def stage1_then_stage2() -> None:
            tcp_timeout = max(2.0, min(timeout / 3, 4.0))
            self._post(lambda: self.log_status(
                f"Стадия 1/2: TCP-предчек {total} хостов (по {tcp_timeout:.0f}с)…"
            ))

            survivors: list[Proxy] = []
            tcp_done = {"n": 0}
            tcp_lock = threading.Lock()

            def tcp_probe(p: Proxy) -> None:
                if self.cancel_event.is_set():
                    return
                ok, why = _tcp_reachable(p.address, p.port, tcp_timeout)
                with tcp_lock:
                    tcp_done["n"] += 1
                    n = tcp_done["n"]
                    if ok:
                        survivors.append(p)
                if not ok:
                    p.status = STATUS_FAIL
                    p.ping_ms = -1
                    p.error = why
                    self._post(lambda pp=p: self._update_row(pp))
                if n % 50 == 0 or n == total:
                    progress = 0.5 * n / max(1, total)  # стадия 1 — первые 50%
                    self._post(lambda pr=progress: self.progress.set(pr))
                    self._post(lambda nn=n, t=total, sv=len(survivors): self.log_status(
                        f"TCP-предчек: {nn}/{t} (живых: {sv})"
                    ))

            with ThreadPoolExecutor(max_workers=64, thread_name_prefix="tcp") as tcp_ex:
                list(tcp_ex.map(tcp_probe, proxies))

            if self.cancel_event.is_set():
                self._post(finalize)
                return

            self._post(lambda sv=len(survivors), t=total: self.log_status(
                f"Стадия 2/2: полный xray-чек {sv} живых хостов из {t} (потоков: {threads})"
            ))
            self._post(self._update_counter)

            # Стадия 2 — реальный xray-чек только для выживших.
            self.executor = ThreadPoolExecutor(
                max_workers=max(1, threads), thread_name_prefix="check"
            )
            self.running_futures = []

            def task(p: Proxy) -> None:
                if self.cancel_event.is_set():
                    p.status = STATUS_PENDING
                    self._post(lambda pp=p: self._update_row(pp))
                    return
                res = check_proxy(p, xray_path, timeout, test_url, self.cancel_event)
                p.status = STATUS_OK if res.ok else STATUS_FAIL
                p.ping_ms = res.ping_ms
                p.error = res.error
                done["n"] += 1
                n = done["n"]

                def apply() -> None:
                    self._update_row(p)
                    # стадия 2 — оставшиеся 50% прогресса
                    self.progress.set(0.5 + 0.5 * n / max(1, len(survivors)))
                    self.log_status(
                        f"Проверка: {n}/{len(survivors)}  ({p.short_addr()} → {p.status})"
                    )
                    self._update_counter()

                self._post(apply)

            for p in survivors:
                fut = self.executor.submit(task, p)
                self.running_futures.append(fut)

            for fut in self.running_futures:
                try:
                    fut.result()
                except Exception:  # noqa: BLE001
                    pass

            self._post(finalize)

        def finalize() -> None:
            self.is_checking = False
            self.executor = None
            # Перерисовка с новой сортировкой: рабочие IPv6 → рабочие IPv4
            # → проверяющиеся → нерабочие, по возрастанию пинга.
            self._refresh_table()
            if self.cancel_event.is_set():
                self.log_status("Проверка остановлена.")
            else:
                ok = sum(1 for p in self.proxies.values() if p.status == STATUS_OK)
                # Группируем ошибки по префиксу до двоеточия (`tcp:`,
                # `tls:`, `http:`, `xray:`, `dns:`, …) — пользователю
                # сразу видно, ЧТО валится. Показываем топ-5 категорий.
                cats: dict[str, int] = {}
                for p in self.proxies.values():
                    if p.status == STATUS_FAIL and p.error:
                        cat = p.error.split(":", 1)[0].strip() or "?"
                        cats[cat] = cats.get(cat, 0) + 1
                if cats:
                    top = sorted(cats.items(), key=lambda x: -x[1])[:5]
                    breakdown = ", ".join(f"{k}: {v}" for k, v in top)
                    self.log_status(
                        f"Проверка завершена. Рабочих: {ok}. Причины фейлов: {breakdown}"
                    )
                else:
                    self.log_status(f"Проверка завершена. Рабочих: {ok}")
            self.after(1500, lambda: self.progress.set(0))

        # Старт стадии 1 в фоне.
        threading.Thread(target=stage1_then_stage2, daemon=True, name="stage1").start()

    # ------------------------------------------------------------ Авто-обновление
    def _schedule_auto_refresh(self) -> None:
        if self._auto_after_id is not None:
            with contextlib.suppress(Exception):
                self.after_cancel(self._auto_after_id)
            self._auto_after_id = None
        minutes = int(self.settings.get("auto_refresh_min", 0) or 0)
        if minutes <= 0:
            return
        ms = minutes * 60 * 1000

        def tick() -> None:
            self._auto_after_id = None
            if not self.is_scraping:
                self.log_status(f"Авто-обновление (раз в {minutes} мин)…")
                self.action_refresh()
            self._schedule_auto_refresh()

        self._auto_after_id = self.after(ms, tick)


# =============================================================================
#                                ENTRYPOINT
# =============================================================================

def main() -> None:
    os.makedirs(TEMP_DIR, exist_ok=True)
    # Гарантируем дефолтные файлы конфига при первом запуске.
    if not os.path.exists(SETTINGS_PATH):
        save_settings(DEFAULT_SETTINGS)
    if not os.path.exists(SOURCES_PATH):
        save_sources(DEFAULT_SOURCES)
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
