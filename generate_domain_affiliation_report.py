#!/usr/bin/env python3
"""
Generate a Markdown report that analyzes relationships and possible affiliations
between domains in a WHOIS/DNS/HTTP/TLS enrichment XLSX.

Input: whois_sites_full.xlsx (default)
Output: domain_affiliation_report.md (default)

Notes:
- The report intentionally does NOT dump raw WHOIS text or full contact PII.
- It uses infrastructure and web-layer indicators to suggest clusters.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

import pandas as pd

INPUT_XLSX_DEFAULT = "whois_sites_full.xlsx"
OUTPUT_MD_DEFAULT = "domain_affiliation_report.md"

PRIVACY_TOKENS = (
    "privacy",
    "redacted",
    "withheld",
    "whoisproxy",
    "privacyguardian",
    "domains by proxy",
    "whois privacy",
    "idcprivacy",
    "private person",
    "privacy protect",
    "personal data",
    "publicly disclosed",
    "registration private",
    "registrant private",
    "private registration",
    "gdpr",
)

CDN_TOKENS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "imperva",
    "incapsula",
)

DDOS_TOKENS = (
    "ddos-guard",
    "qrator",
)

MAJOR_NS_PROVIDERS = {
    "cloudflare.com",
    "reg.ru",
    "nic.ru",
    "r01.ru",
    "yandex.net",
    "beget.com",
    "beget.pro",
    "jino.ru",
    "selectel.ru",
    "ddos-guard.net",
    "rambler.ru",
}

MAJOR_MX_PROVIDERS = {
    "google.com",
    "googlemail.com",
    "yandex.net",
    "mail.ru",
    "zoho.eu",
    "outlook.com",
    "hotmail.com",
    "rambler.ru",
    "rambler-co.ru",
}

ORG_NAME_TOKENS = (
    "ооо",
    "оао",
    "зао",
    "пао",
    "ао",
    "ип ",
    "llc",
    "ltd",
    "inc",
    "corp",
    "company",
    "co.",
    "gmbh",
    "s.a",
    "s.a.",
    "s.r.l",
    "ag",
    "bv",
    "nv",
    "plc",
    "pty",
    "holding",
    "group",
    "foundation",
    "agency",
    "bank",
    "university",
    "institute",
)

STRONG_COLUMNS = {
    "whois_org",
    "whois_registrant_org",
    "whois_registrant_name",
    "whois_admin_org",
    "whois_admin_name",
    "whois_tech_org",
    "whois_tech_name",
    "whois_registrant_email",
    "whois_admin_email",
    "whois_tech_email",
    "whois_billing_email",
    "dns_SOA",
}

COLUMN_GROUP_WEIGHTS = {
    "WHOIS": 3,
    "DNS": 2,
    "HTTP": 1,
    "TLS": 2,
    "Trackers": 2,
    "Network": 2,
    "Other": 1,
}

STRONG_COLUMN_WEIGHT = 4
MERGE_SCORE_THRESHOLD = 6
MAX_CLUSTER_RATIO = 0.1
MERGE_ALLOWED_GROUPS = {"WHOIS", "DNS", "Trackers", "Network"}


def json_loads_maybe(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, float) and pd.isna(value):
        return default
    if not isinstance(value, str):
        return default
    s = value.strip()
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def cell_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    s = str(value).strip()
    return "" if s.lower() == "nan" else s


def ast_eval_maybe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    if not isinstance(value, str):
        return value
    s = value.strip()
    if not s or s.lower() == "nan":
        return None
    try:
        return ast.literal_eval(s)
    except Exception:
        return None


def normalize_host(host: str) -> str:
    host = str(host).strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def base_domain(host: str) -> str:
    host = normalize_host(host)
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def parse_mx_host(entry: str) -> str:
    parts = str(entry).strip().strip('"').split()
    host = parts[-1]
    return normalize_host(host)


def final_host(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return ""
    return normalize_host(host)


def is_privacy_org(org: str) -> bool:
    if not org:
        return True
    low = org.lower()
    return any(t in low for t in PRIVACY_TOKENS)


def asn_class(as_str: str) -> str:
    s = (as_str or "").lower()
    if any(t in s for t in CDN_TOKENS):
        return "cdn"
    if any(t in s for t in DDOS_TOKENS):
        return "ddos"
    return "host"


def extract_cn(subject_or_issuer: Any) -> str:
    if subject_or_issuer is None:
        return ""
    s = str(subject_or_issuer)
    m = re.search(r"\('commonName', '([^']+)'\)", s)
    return m.group(1) if m else ""


def extract_tls_san_dns(value: Any) -> List[str]:
    parsed = ast_eval_maybe(value)
    if parsed is None:
        return []
    out: List[str] = []
    if isinstance(parsed, (list, tuple)):
        for item in parsed:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            kind, name = item[0], item[1]
            if str(kind).upper() == "DNS":
                out.append(normalize_host(name))
    return sorted(set(out))


def extract_tls_orgs(value: Any) -> List[str]:
    parsed = ast_eval_maybe(value)
    orgs: Set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk((k, v))
            return
        if isinstance(node, (list, tuple)):
            if len(node) == 2 and isinstance(node[0], str):
                key = node[0].strip()
                if key in {"organizationName", "organization", "O"}:
                    name = normalize_entity_name(node[1])
                    if name:
                        orgs.add(name)
            for item in node:
                walk(item)

    if parsed is not None:
        walk(parsed)
    else:
        s = cell_str(value)
        if s:
            for m in re.finditer(r"\('organizationName', '([^']+)'\)", s):
                orgs.add(m.group(1).strip())

    return sorted(orgs)


def extract_email_domains(value: Any) -> List[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    s = str(value)

    email_domain_re = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.I)
    domains: Set[str] = set()

    data = json_loads_maybe(s, None)
    if isinstance(data, list):
        for item in data:
            for dom in email_domain_re.findall(str(item)):
                domains.add(dom.lower())
    else:
        for dom in email_domain_re.findall(s):
            domains.add(dom.lower())

    return sorted(domains)


def extract_soa_email_domains(value: Any) -> List[str]:
    entries = json_loads_maybe(value, [])
    if not isinstance(entries, list):
        entries = [value] if value else []
    domains: Set[str] = set()
    for entry in entries:
        s = str(entry or "").strip().strip('"')
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        rname = parts[1].strip().rstrip(".")
        if "@" in rname:
            rname = rname.split("@", 1)[-1]
        elif "." in rname:
            rname = rname.split(".", 1)[-1]
        rname = rname.strip().strip(".")
        if rname:
            domains.add(rname.lower())
    return sorted(domains)


def normalize_entity_name(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def is_privacy_value(value: Any) -> bool:
    s = normalize_entity_name(value).lower()
    if not s:
        return True
    if s in {"n/a", "na", "none", "not available", "not disclosed", "redacted"}:
        return True
    return any(t in s for t in PRIVACY_TOKENS) or "privacy" in s or "redacted" in s


def is_org_like_name(value: Any) -> bool:
    s = normalize_entity_name(value).lower()
    if not s:
        return False
    return any(token in s for token in ORG_NAME_TOKENS)


def parse_json_list(value: Any) -> List[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    data = json_loads_maybe(value, None)
    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()]
    parsed = ast_eval_maybe(value)
    if isinstance(parsed, list):
        return [str(x).strip() for x in parsed if str(x).strip()]
    s = cell_str(value)
    return [s] if s else []


def md_escape(value: Any) -> str:
    s = "" if value is None else str(value)
    s = s.replace("|", "\\|")
    s = s.replace("\n", "<br>")
    return s


def scalar_to_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def token_key_and_display(value: Any, column: str) -> Optional[Tuple[str, str]]:
    raw = scalar_to_str(value).strip()
    if not raw or raw.lower() == "nan":
        return None
    if column.startswith("whois_") and is_privacy_value(raw):
        return None
    display = re.sub(r"\s+", " ", raw)
    if len(display) > 140:
        display = display[:137] + "…"
    if column.startswith("trackers_"):
        display = display.upper()
    key = display.lower()
    if column.startswith("trackers_"):
        key = display
    if len(raw) > 200:
        digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
        key = f"hash:{digest}"
    return key, display


def extract_http_headers_tokens(value: Any, column: str) -> List[Tuple[str, str]]:
    parsed = json_loads_maybe(value, None)
    if parsed is None:
        parsed = ast_eval_maybe(value)
    if not isinstance(parsed, dict):
        return []
    tokens: List[Tuple[str, str]] = []
    for k, v in parsed.items():
        if v is None:
            continue
        token = token_key_and_display(f"{k}={v}", column)
        if token:
            tokens.append(token)
    return tokens


def extract_geoip_tokens(value: Any, column: str) -> List[Tuple[str, str]]:
    parsed = json_loads_maybe(value, None)
    if parsed is None:
        parsed = ast_eval_maybe(value)
    if not isinstance(parsed, dict):
        return []
    tokens: List[Tuple[str, str]] = []
    for ip, info in parsed.items():
        if isinstance(info, dict):
            for key in ("as", "asname", "org", "isp", "country"):
                val = info.get(key)
                if val:
                    token = token_key_and_display(f"{key}={val}", column)
                    if token:
                        tokens.append(token)
        token = token_key_and_display(f"ip={ip}", column)
        if token:
            tokens.append(token)
    return tokens


def extract_reverse_dns_tokens(value: Any, column: str) -> List[Tuple[str, str]]:
    parsed = json_loads_maybe(value, None)
    if parsed is None:
        parsed = ast_eval_maybe(value)
    if not isinstance(parsed, dict):
        return []
    tokens: List[Tuple[str, str]] = []
    for _, host in parsed.items():
        token = token_key_and_display(host, column)
        if token:
            tokens.append(token)
    return tokens


def extract_tls_name_tokens(value: Any, column: str) -> List[Tuple[str, str]]:
    s = cell_str(value)
    if not s:
        return []
    tokens: List[Tuple[str, str]] = []
    for m in re.finditer(r"\\('commonName', '([^']+)'\\)", s):
        token = token_key_and_display(f"cn={m.group(1)}", column)
        if token:
            tokens.append(token)
    for m in re.finditer(r"\\('organizationName', '([^']+)'\\)", s):
        token = token_key_and_display(f"o={m.group(1)}", column)
        if token:
            tokens.append(token)
    if tokens:
        return tokens
    token = token_key_and_display(s, column)
    return [token] if token else []


def extract_tls_san_tokens(value: Any, column: str) -> List[Tuple[str, str]]:
    parsed = ast_eval_maybe(value)
    if parsed is None:
        parsed = json_loads_maybe(value, None)
    if not isinstance(parsed, (list, tuple)):
        return []
    tokens: List[Tuple[str, str]] = []
    for item in parsed:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        kind, name = item[0], item[1]
        if str(kind).upper() == "DNS":
            token = token_key_and_display(name, column)
            if token:
                tokens.append(token)
    return tokens


def extract_tokens_from_value(column: str, value: Any) -> List[Tuple[str, str]]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    if column == "http_headers":
        return extract_http_headers_tokens(value, column)
    if column == "geoip":
        return extract_geoip_tokens(value, column)
    if column == "reverse_dns":
        return extract_reverse_dns_tokens(value, column)
    if column in {"tls_subject", "tls_issuer"}:
        return extract_tls_name_tokens(value, column)
    if column == "tls_subjectAltName":
        return extract_tls_san_tokens(value, column)

    if isinstance(value, str):
        s = value.strip()
        if not s or s.lower() == "nan":
            return []
        if s.startswith("{") or s.startswith("["):
            parsed = json_loads_maybe(s, None)
            if parsed is None:
                parsed = ast_eval_maybe(s)
            if parsed is not None:
                return extract_tokens_from_value(column, parsed)
        token = token_key_and_display(s, column)
        return [token] if token else []

    if isinstance(value, dict):
        tokens: List[Tuple[str, str]] = []
        for k, v in value.items():
            if isinstance(v, (list, tuple, set, dict)):
                tokens.extend(extract_tokens_from_value(column, v))
            else:
                token = token_key_and_display(f"{k}={v}", column)
                if token:
                    tokens.append(token)
        return tokens

    if isinstance(value, (list, tuple, set)):
        tokens: List[Tuple[str, str]] = []
        for item in value:
            tokens.extend(extract_tokens_from_value(column, item))
        return tokens

    token = token_key_and_display(value, column)
    return [token] if token else []


def column_group_name(column: str) -> str:
    if column.startswith("whois_"):
        return "WHOIS"
    if column.startswith("dns_"):
        return "DNS"
    if column.startswith("http_"):
        return "HTTP"
    if column.startswith("tls_"):
        return "TLS"
    if column.startswith("trackers_"):
        return "Trackers"
    if column in {"ip_list", "reverse_dns", "geoip"} or column.startswith("ip_"):
        return "Network"
    return "Other"


def column_weight(column: str) -> int:
    if column in STRONG_COLUMNS:
        return STRONG_COLUMN_WEIGHT
    return COLUMN_GROUP_WEIGHTS.get(column_group_name(column), 1)


def ensure_min_words(text: str, min_words: int = 100) -> str:
    words = [w for w in re.split(r"\s+", text.strip()) if w]
    filler = (
        "При необходимости можно сузить выборку, перепроверить исходные источники и "
        "сопоставить результаты с альтернативными данными, чтобы повысить надежность выводов."
    )
    while len(words) < min_words:
        text = text + " " + filler
        words = [w for w in re.split(r"\s+", text.strip()) if w]
    return text


def table_analysis_text(row_count: int) -> str:
    text = (
        "Этот аналитический блок относится к таблице выше и поясняет, как интерпретировать ее значения. "
        f"Таблица содержит {row_count} строк и отражает наблюдения, которые были автоматически извлечены "
        "из инфраструктурных и веб-слоев. Подчеркну, что такие индикаторы показывают связи на уровне "
        "сервисов и конфигураций, а не юридическое владение. Высокие частоты обычно указывают на массовые "
        "платформы, CDN, почтовых провайдеров или рекламные системы, поэтому они полезны для выявления "
        "общих поставщиков услуг. Низкие частоты могут быть более специфичными, но их нужно проверять "
        "вручную, так как сбор неполный и часть сигналов может быть скрыта или динамически подгружена. "
        "Используйте эту таблицу как карту гипотез, сопоставляя строки с WHOIS, DNS, TLS и треккерами, "
        "а также проверяя историю доменов и стабильность IP. При необходимости повторите сбор и сравните "
        "динамику результатов."
    )
    return ensure_min_words(text, min_words=100)


def md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = []
    lines.append("| " + " | ".join(md_escape(h) for h in headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(md_escape(c) for c in row) + " |")
    table = "\n".join(lines)
    analysis = table_analysis_text(len(rows))
    return table + "\n\n" + analysis


def build_cluster_evidence(
    cluster_domains: Set[str],
    column_clusters: Dict[str, Dict[str, Set[str]]],
    column_token_display: Dict[str, Dict[str, str]],
    max_cluster_size: int,
    max_rows: int = 25,
) -> Tuple[List[Tuple[int, str, str, List[str]]], Counter, Counter]:
    all_rows: List[Tuple[int, str, str, List[str]]] = []
    for col, value_map in column_clusters.items():
        for key, doms in value_map.items():
            if col not in STRONG_COLUMNS and len(doms) > max_cluster_size:
                continue
            shared = sorted(cluster_domains & doms)
            if len(shared) < 2:
                continue
            display = column_token_display.get(col, {}).get(key, key)
            all_rows.append((len(shared), col, display, shared))
    all_rows.sort(key=lambda x: (-x[0], x[1], x[2]))
    group_counts = Counter(column_group_name(col) for _, col, _, _ in all_rows)
    column_counts = Counter(col for _, col, _, _ in all_rows)
    return all_rows[:max_rows], group_counts, column_counts


def case_analysis_text(
    case_id: int,
    cluster_domains: Sequence[str],
    evidence_rows: Sequence[Tuple[int, str, str, List[str]]],
    group_counts: Counter,
    column_counts: Counter,
) -> str:
    size = len(cluster_domains)
    top_groups = [g for g, _ in group_counts.most_common(3)]
    top_cols = [c for c, _ in column_counts.most_common(3)]

    top_values = []
    for cnt, col, value, _ in evidence_rows[:2]:
        top_values.append(f"{col}={value} (домены: {cnt})")
    values_text = "; ".join(top_values) if top_values else "существенных повторов по значениям не найдено"

    text = (
        f"Кейс #{case_id} объединяет {size} доменов, связанных совпадениями значений по множеству столбцов таблицы. "
        f"Для объединения использовалось сопоставление кластеров по каждому столбцу и последующее укрупнение "
        f"по суммарному весу пересечений; такой подход снижает риск случайных совпадений и делает кластеризацию "
        f"более интерпретируемой. В данном кейсе наиболее заметны группы сигналов: {', '.join(top_groups) if top_groups else 'нет доминирующей группы'}, "
        f"а чаще всего повторяются столбцы: {', '.join(top_cols) if top_cols else 'нет повторяющихся колонок'}. "
        f"Ключевые совпадения выглядят так: {values_text}. Эти совпадения указывают на возможную общую инфраструктуру, "
        f"операционные связи или единые маркетинговые контуры, однако не являются прямым доказательством владения. "
        f"Рекомендуется перепроверить домены из кластера по WHOIS/RDAP, истории DNS и стабильности IP, а также "
        f"оценить устойчивость треккерных ID и редиректов во времени."
    )
    return ensure_min_words(text, min_words=120)


def fmt_list(items: Sequence[str], max_items: int = 6) -> str:
    items = [str(x) for x in items if x]
    if not items:
        return ""
    if len(items) <= max_items:
        return "<br>".join(items)
    head = items[:max_items]
    return "<br>".join(head) + f"<br>… (+{len(items) - max_items})"


@dataclass(frozen=True)
class DomainInfo:
    domain: str
    domain_input: str
    ok: bool
    error: str

    ips: List[str]
    non_cdn_ips: List[str]
    cdn_ips: List[str]
    ddos_ips: List[str]
    ip_as: Dict[str, str]
    ip_country: Dict[str, str]
    ip_city: Dict[str, str]
    reverse_dns: Dict[str, Optional[str]]

    ns: List[str]
    ns_providers: List[str]
    mx_hosts: List[str]
    mx_providers: List[str]
    txt: List[str]
    soa: List[str]

    whois_registrar: str
    whois_org: str
    whois_org_is_privacy: bool
    whois_email_domains: List[str]
    registrant_org: str
    registrant_name: str
    whois_admin_org: str
    whois_admin_name: str
    whois_tech_org: str
    whois_tech_name: str
    whois_admin_email_domains: List[str]
    whois_tech_email_domains: List[str]
    whois_registrant_email_domains: List[str]
    whois_billing_email_domains: List[str]
    dns_soa_email_domains: List[str]

    http_status_code: Optional[int]
    http_final_url: str
    http_final_host: str
    http_server: str
    http_title: str

    tls_subject_cn: str
    tls_issuer_cn: str
    tls_not_after: str
    tls_san_dns: List[str]
    tls_subject_orgs: List[str]

    tracker_ym_ids: List[str]
    tracker_ga_ua_ids: List[str]
    tracker_ga4_ids: List[str]
    tracker_gads_aw_ids: List[str]
    tracker_gads_conversion_labels: List[str]
    tracker_gtm_ids: List[str]
    tracker_fb_pixel_ids: List[str]


def build_domain_infos(df: pd.DataFrame) -> Dict[str, DomainInfo]:
    infos: Dict[str, DomainInfo] = {}
    for _, row in df.iterrows():
        domain = str(row.get("domain") or "").strip().lower()
        if not domain:
            continue

        ips = list(dict.fromkeys(json_loads_maybe(row.get("ip_list"), [])))
        geo = json_loads_maybe(row.get("geoip"), {})

        ip_as: Dict[str, str] = {}
        ip_country: Dict[str, str] = {}
        ip_city: Dict[str, str] = {}
        for ip in ips:
            info = geo.get(ip) if isinstance(geo, dict) else None
            if isinstance(info, dict):
                ip_as[ip] = str(info.get("as") or "")
                ip_country[ip] = str(info.get("country") or "")
                ip_city[ip] = str(info.get("city") or "")

        non_cdn_ips = [ip for ip in ips if asn_class(ip_as.get(ip, "")) == "host"]
        cdn_ips = [ip for ip in ips if asn_class(ip_as.get(ip, "")) == "cdn"]
        ddos_ips = [ip for ip in ips if asn_class(ip_as.get(ip, "")) == "ddos"]

        reverse_dns = json_loads_maybe(row.get("reverse_dns"), {})
        reverse_dns = reverse_dns if isinstance(reverse_dns, dict) else {}

        ns = [normalize_host(x) for x in json_loads_maybe(row.get("dns_NS"), [])]
        ns_providers = sorted({base_domain(x) for x in ns if x})

        mx_hosts = [parse_mx_host(x) for x in json_loads_maybe(row.get("dns_MX"), [])]
        mx_providers = sorted({base_domain(x) for x in mx_hosts if x})

        txt = [str(x) for x in json_loads_maybe(row.get("dns_TXT"), [])]
        soa = [str(x) for x in json_loads_maybe(row.get("dns_SOA"), [])]

        whois_org = cell_str(row.get("whois_org"))
        registrant_org = cell_str(row.get("whois_registrant_org")) or whois_org
        registrant_name = cell_str(row.get("whois_registrant_name")) or cell_str(row.get("whois_name"))
        whois_admin_org = cell_str(row.get("whois_admin_org"))
        whois_admin_name = cell_str(row.get("whois_admin_name"))
        whois_tech_org = cell_str(row.get("whois_tech_org"))
        whois_tech_name = cell_str(row.get("whois_tech_name"))
        whois_admin_email_domains = extract_email_domains(row.get("whois_admin_email"))
        whois_tech_email_domains = extract_email_domains(row.get("whois_tech_email"))
        whois_registrant_email_domains = extract_email_domains(row.get("whois_registrant_email"))
        whois_billing_email_domains = extract_email_domains(row.get("whois_billing_email"))
        dns_soa_email_domains = extract_soa_email_domains(row.get("dns_SOA"))

        http_final_url = cell_str(row.get("http_final_url"))
        http_final_host = final_host(http_final_url) if http_final_url else ""

        status_code = None
        raw_code = row.get("http_status_code")
        if raw_code is not None and not (isinstance(raw_code, float) and pd.isna(raw_code)):
            try:
                status_code = int(float(raw_code))
            except Exception:
                status_code = None

        tls_subject_cn = extract_cn(row.get("tls_subject"))
        tls_issuer_cn = extract_cn(row.get("tls_issuer"))
        tls_not_after = cell_str(row.get("tls_notAfter"))
        tls_san_dns = extract_tls_san_dns(row.get("tls_subjectAltName"))
        tls_subject_orgs = extract_tls_orgs(row.get("tls_subject"))
        tracker_ym_ids = parse_json_list(row.get("trackers_ym_ids"))
        tracker_ga_ua_ids = parse_json_list(row.get("trackers_ga_ua_ids"))
        tracker_ga4_ids = parse_json_list(row.get("trackers_ga4_ids"))
        tracker_gads_aw_ids = parse_json_list(row.get("trackers_gads_aw_ids"))
        tracker_gads_conversion_labels = parse_json_list(row.get("trackers_gads_conversion_labels"))
        tracker_gtm_ids = parse_json_list(row.get("trackers_gtm_ids"))
        tracker_fb_pixel_ids = parse_json_list(row.get("trackers_fb_pixel_ids"))

        infos[domain] = DomainInfo(
            domain=domain,
            domain_input=cell_str(row.get("domain_input")),
            ok=bool(row.get("ok")) if row.get("ok") is not None else False,
            error=cell_str(row.get("error")),
            ips=ips,
            non_cdn_ips=non_cdn_ips,
            cdn_ips=cdn_ips,
            ddos_ips=ddos_ips,
            ip_as=ip_as,
            ip_country=ip_country,
            ip_city=ip_city,
            reverse_dns={str(k): (None if v in (None, "", "null") else str(v)) for k, v in reverse_dns.items()},
            ns=ns,
            ns_providers=ns_providers,
            mx_hosts=mx_hosts,
            mx_providers=mx_providers,
            txt=txt,
            soa=soa,
            whois_registrar=cell_str(row.get("whois_registrar")),
            whois_org=whois_org,
            whois_org_is_privacy=is_privacy_org(whois_org),
            whois_email_domains=extract_email_domains(row.get("whois_emails")),
            registrant_org=registrant_org,
            registrant_name=registrant_name,
            whois_admin_org=whois_admin_org,
            whois_admin_name=whois_admin_name,
            whois_tech_org=whois_tech_org,
            whois_tech_name=whois_tech_name,
            whois_admin_email_domains=whois_admin_email_domains,
            whois_tech_email_domains=whois_tech_email_domains,
            whois_registrant_email_domains=whois_registrant_email_domains,
            whois_billing_email_domains=whois_billing_email_domains,
            dns_soa_email_domains=dns_soa_email_domains,
            http_status_code=status_code,
            http_final_url=http_final_url,
            http_final_host=http_final_host,
            http_server=cell_str(row.get("http_server")),
            http_title=cell_str(row.get("http_title")),
            tls_subject_cn=tls_subject_cn,
            tls_issuer_cn=tls_issuer_cn,
            tls_not_after=tls_not_after,
            tls_san_dns=tls_san_dns,
            tls_subject_orgs=tls_subject_orgs,
            tracker_ym_ids=tracker_ym_ids,
            tracker_ga_ua_ids=tracker_ga_ua_ids,
            tracker_ga4_ids=tracker_ga4_ids,
            tracker_gads_aw_ids=tracker_gads_aw_ids,
            tracker_gads_conversion_labels=tracker_gads_conversion_labels,
            tracker_gtm_ids=tracker_gtm_ids,
            tracker_fb_pixel_ids=tracker_fb_pixel_ids,
        )

    return infos


def group_by(values: Iterable[Tuple[str, str]]) -> Dict[str, List[str]]:
    m: Dict[str, List[str]] = defaultdict(list)
    for key, domain in values:
        if not key:
            continue
        m[key].append(domain)
    for k in list(m.keys()):
        m[k] = sorted(set(m[k]))
    return m


def build_report(df: pd.DataFrame, infos: Dict[str, DomainInfo]) -> str:
    domains = sorted(infos.keys())
    total = len(domains)
    ok = sum(1 for d in domains if infos[d].ok)
    http_ok = sum(1 for d in domains if infos[d].http_status_code is not None)
    tls_ok = sum(1 for d in domains if infos[d].tls_not_after)
    whois_org_present = sum(1 for d in domains if infos[d].whois_org and not infos[d].whois_org_is_privacy)
    tracker_any = sum(
        1
        for d in domains
        if (
            infos[d].tracker_ym_ids
            or infos[d].tracker_ga_ua_ids
            or infos[d].tracker_ga4_ids
            or infos[d].tracker_gads_aw_ids
            or infos[d].tracker_gads_conversion_labels
            or infos[d].tracker_gtm_ids
            or infos[d].tracker_fb_pixel_ids
        )
    )
    tracker_ym = sum(1 for d in domains if infos[d].tracker_ym_ids)
    tracker_ga_ua = sum(1 for d in domains if infos[d].tracker_ga_ua_ids)
    tracker_ga4 = sum(1 for d in domains if infos[d].tracker_ga4_ids)
    tracker_gads = sum(1 for d in domains if infos[d].tracker_gads_aw_ids)
    tracker_gads_labels = sum(1 for d in domains if infos[d].tracker_gads_conversion_labels)
    tracker_gtm = sum(1 for d in domains if infos[d].tracker_gtm_ids)
    tracker_fb = sum(1 for d in domains if infos[d].tracker_fb_pixel_ids)

    tracker_ym_counter = Counter(t for d in domains for t in infos[d].tracker_ym_ids)
    tracker_ga_ua_counter = Counter(t for d in domains for t in infos[d].tracker_ga_ua_ids)
    tracker_ga4_counter = Counter(t for d in domains for t in infos[d].tracker_ga4_ids)
    tracker_gtm_counter = Counter(t for d in domains for t in infos[d].tracker_gtm_ids)
    tracker_gads_counter = Counter(t for d in domains for t in infos[d].tracker_gads_aw_ids)
    tracker_gads_label_counter = Counter(t for d in domains for t in infos[d].tracker_gads_conversion_labels)
    tracker_fb_counter = Counter(t for d in domains for t in infos[d].tracker_fb_pixel_ids)

    domain_set = set(domains)
    column_clusters: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    column_token_display: Dict[str, Dict[str, str]] = defaultdict(dict)

    for _, row in df.iterrows():
        dom = str(row.get("domain") or "").strip().lower()
        if not dom:
            dom = str(row.get("domain_input") or "").strip().lower()
        if not dom or dom not in domain_set:
            continue
        for col in df.columns:
            tokens = extract_tokens_from_value(col, row.get(col))
            for token in tokens:
                if not token:
                    continue
                key, display = token
                column_clusters[col][key].add(dom)
                if key not in column_token_display[col]:
                    column_token_display[col][key] = display

    max_cluster_size = max(3, int(total * MAX_CLUSTER_RATIO))
    pair_columns: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for col, value_map in column_clusters.items():
        group_name = column_group_name(col)
        if col not in STRONG_COLUMNS and group_name not in MERGE_ALLOWED_GROUPS:
            continue
        for _, doms in value_map.items():
            if len(doms) < 2:
                continue
            if col not in STRONG_COLUMNS and len(doms) > max_cluster_size:
                continue
            dom_list = sorted(doms)
            for i in range(len(dom_list)):
                for j in range(i + 1, len(dom_list)):
                    pair_columns[(dom_list[i], dom_list[j])].add(col)

    pair_scores: Dict[Tuple[str, str], int] = {}
    for pair, cols in pair_columns.items():
        score = sum(column_weight(c) for c in cols)
        pair_scores[pair] = score

    parent = {d: d for d in domains}
    rank = {d: 0 for d in domains}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            parent[ra] = rb
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
        else:
            parent[rb] = ra
            rank[ra] += 1

    edges: List[Tuple[str, str, int, List[str]]] = []
    for (a, b), score in pair_scores.items():
        cols = sorted(pair_columns.get((a, b), []))
        edges.append((a, b, score, cols))
        has_strong = any(c in STRONG_COLUMNS for c in cols)
        group_count = len({column_group_name(c) for c in cols})
        if (has_strong and score >= STRONG_COLUMN_WEIGHT) or (
            score >= MERGE_SCORE_THRESHOLD and group_count >= 2
        ):
            union(a, b)

    clusters = defaultdict(list)
    for d in domains:
        clusters[find(d)].append(d)
    cluster_list = sorted([sorted(v) for v in clusters.values() if len(v) > 1], key=lambda x: (-len(x), x[0]))

    org_groups: Dict[str, Set[str]] = defaultdict(set)
    org_display: Dict[str, str] = {}
    org_roles: Dict[str, Set[str]] = defaultdict(set)
    person_groups: Dict[str, Set[str]] = defaultdict(set)
    person_display: Dict[str, str] = {}
    person_roles: Dict[str, Set[str]] = defaultdict(set)
    email_domain_groups: Dict[str, Set[str]] = defaultdict(set)
    tls_org_groups: Dict[str, Set[str]] = defaultdict(set)
    tls_org_display: Dict[str, str] = {}

    role_labels = {
        "registrant_org": "registrant org",
        "registrant_name": "registrant name",
        "whois_org": "whois org",
        "admin_org": "admin org",
        "admin_name": "admin name",
        "tech_org": "tech org",
        "tech_name": "tech name",
    }

    def add_entity(
        groups: Dict[str, Set[str]],
        display: Dict[str, str],
        roles: Dict[str, Set[str]],
        name: str,
        domain: str,
        role: str,
    ) -> None:
        clean = normalize_entity_name(name)
        if not clean or is_privacy_value(clean):
            return
        key = clean.lower()
        groups[key].add(domain)
        display.setdefault(key, clean)
        roles[key].add(role)

    for d in domains:
        info = infos[d]
        add_entity(org_groups, org_display, org_roles, info.registrant_org, d, "registrant_org")
        add_entity(org_groups, org_display, org_roles, info.whois_org, d, "whois_org")
        add_entity(org_groups, org_display, org_roles, info.whois_admin_org, d, "admin_org")
        add_entity(org_groups, org_display, org_roles, info.whois_tech_org, d, "tech_org")

        for name, role in [
            (info.registrant_name, "registrant_name"),
            (info.whois_admin_name, "admin_name"),
            (info.whois_tech_name, "tech_name"),
        ]:
            clean = normalize_entity_name(name)
            if not clean or is_privacy_value(clean):
                continue
            if is_org_like_name(clean):
                add_entity(org_groups, org_display, org_roles, clean, d, role)
            else:
                add_entity(person_groups, person_display, person_roles, clean, d, role)

        email_domains = set(
            info.whois_email_domains
            + info.whois_admin_email_domains
            + info.whois_tech_email_domains
            + info.whois_registrant_email_domains
            + info.whois_billing_email_domains
            + info.dns_soa_email_domains
        )
        for dom in email_domains:
            if dom:
                email_domain_groups[dom.lower()].add(d)

        for org in info.tls_subject_orgs:
            clean = normalize_entity_name(org)
            if not clean or is_privacy_value(clean):
                continue
            key = clean.lower()
            tls_org_groups[key].add(d)
            tls_org_display.setdefault(key, clean)

    def format_roles(roles: Set[str]) -> str:
        labels = [role_labels.get(r, r) for r in sorted(roles)]
        return ", ".join(labels)

    org_list = sorted(
        [(org_display[k], sorted(org_groups[k]), format_roles(org_roles[k])) for k in org_groups],
        key=lambda x: (-len(x[1]), x[0].lower()),
    )
    person_list = sorted(
        [(person_display[k], sorted(person_groups[k]), format_roles(person_roles[k])) for k in person_groups],
        key=lambda x: (-len(x[1]), x[0].lower()),
    )
    email_domain_list = sorted(
        [(dom, sorted(ds)) for dom, ds in email_domain_groups.items()],
        key=lambda x: (-len(x[1]), x[0]),
    )
    tls_org_list = sorted(
        [(tls_org_display[k], sorted(ds)) for k, ds in tls_org_groups.items()],
        key=lambda x: (-len(x[1]), x[0].lower()),
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: List[str] = []

    lines.append("# Отчет по связям и кластерам доменов")
    lines.append("")
    lines.append(f"- Сгенерировано: `{now}`")
    lines.append(f"- Источник: `{INPUT_XLSX_DEFAULT}`")
    lines.append("")

    lines.append("## 0) Методика кластеризации")
    lines.append(
        "Кластеризация построена в два этапа. Сначала для каждого столбца таблицы формируются микрокластеры "
        "по совпадающим значениям (включая элементы списков и словарей). Затем эти микрокластеры сопоставляются "
        "между собой: домены объединяются, если суммарный вес совпадений по разным столбцам достигает порога "
        "и совпадения затрагивают как минимум две группы столбцов (или присутствует сильная колонка WHOIS/TLS). "
        "Для укрупнения используются в основном устойчивые группы (WHOIS/DNS/Network/Trackers), а HTTP/TLS "
        "оставлены как подтверждающие признаки. Слишком частые значения, встречающиеся "
        f"более чем у ~{int(MAX_CLUSTER_RATIO * 100)}% доменов, не участвуют в объединении, кроме сильных колонок."
    )
    lines.append("")

    lines.append("## 1) Кейсы кластеров")
    if not cluster_list:
        lines.append("Кластеры по заданной методике не обнаружены. Ниже приведены доказательные таблицы и сводные метрики.")
        lines.append("")
    else:
        for idx, cl in enumerate(cluster_list, start=1):
            lines.append(f"### Кейс #{idx} (n={len(cl)})")
            cluster_set = set(cl)
            evidence_rows, group_counts, column_counts = build_cluster_evidence(
                cluster_set,
                column_clusters,
                column_token_display,
                max_cluster_size,
                max_rows=25,
            )
            lines.append(case_analysis_text(idx, cl, evidence_rows, group_counts, column_counts))
            lines.append("")

            evidence_table_rows = [
                [col, value, cnt, fmt_list(shared, max_items=20)]
                for cnt, col, value, shared in evidence_rows
            ]
            if evidence_table_rows:
                lines.append("**Доказательства: совпадающие значения по столбцам**")
                lines.append(
                    md_table(
                        ["Столбец", "Значение", "Доменов", "Домены"],
                        evidence_table_rows,
                    )
                )
                lines.append("")

            rows = []
            for d in cl:
                info = infos[d]
                primary_ip = info.ips[0] if info.ips else ""
                primary_as = info.ip_as.get(primary_ip, "")
                primary_geo = ", ".join(x for x in [info.ip_country.get(primary_ip, ""), info.ip_city.get(primary_ip, "")] if x)
                rows.append(
                    [
                        d,
                        fmt_list(info.ips, 4),
                        primary_as,
                        primary_geo,
                        fmt_list(info.ns_providers, 3),
                        fmt_list(info.mx_providers, 3),
                        f"{info.http_status_code or ''} → {info.http_final_host or ''}",
                        info.http_server,
                    ]
                )
            lines.append("**Детализация доменов кластера**")
            lines.append(
                md_table(
                    ["Домен", "IP(s)", "ASN (primary)", "Geo (primary)", "NS providers", "MX providers", "HTTP", "Server"],
                    rows,
                )
            )
            lines.append("")

    lines.append("## 2) Оформители и контактные лица (WHOIS)")
    lines.append(
        "В блоке показаны только имена/организации без адресов, телефонов и почты. "
        "Включены registrant/admin/tech. Значения privacy/редактировано исключены."
    )
    lines.append("")
    lines.append("### 2.1 Организации")
    if org_list:
        org_rows = [[name, len(ds), roles, fmt_list(ds, max_items=25)] for name, ds, roles in org_list[:30]]
        lines.append(md_table(["Организация", "Доменов", "Роли", "Домены"], org_rows))
        if len(org_list) > 30:
            lines.append("")
            lines.append(f"_Показаны топ-30 из {len(org_list)} организаций._")
    else:
        lines.append("_Не найдено._")
    lines.append("")
    lines.append("### 2.2 Физические лица")
    if person_list:
        person_rows = [[name, len(ds), roles, fmt_list(ds, max_items=25)] for name, ds, roles in person_list[:30]]
        lines.append(md_table(["ФИО", "Доменов", "Роли", "Домены"], person_rows))
        if len(person_list) > 30:
            lines.append("")
            lines.append(f"_Показаны топ-30 из {len(person_list)} физлиц._")
    else:
        lines.append("_Не найдено._")
    lines.append("")
    lines.append("### 2.3 Email-домены контактов (WHOIS + SOA)")
    lines.append("_Показываются только домены, без самих адресов._")
    if email_domain_list:
        email_rows = [[dom, len(ds), fmt_list(ds, max_items=25)] for dom, ds in email_domain_list[:30]]
        lines.append(md_table(["Email domain", "Доменов", "Домены"], email_rows))
        if len(email_domain_list) > 30:
            lines.append("")
            lines.append(f"_Показаны топ-30 из {len(email_domain_list)} доменов email._")
    else:
        lines.append("_Не найдено._")
    lines.append("")

    lines.append("## 3) Доп. источники организаций (не WHOIS)")
    lines.append("### 3.1 TLS Subject O (организация из сертификата)")
    lines.append("_Может отражать CDN/хостинг или юрлицо, не всегда совпадает с владельцем домена._")
    if tls_org_list:
        tls_rows = [[name, len(ds), fmt_list(ds, max_items=25)] for name, ds in tls_org_list[:30]]
        lines.append(md_table(["Организация", "Доменов", "Домены"], tls_rows))
        if len(tls_org_list) > 30:
            lines.append("")
            lines.append(f"_Показаны топ-30 из {len(tls_org_list)} организаций._")
    else:
        lines.append("_Не найдено._")
    lines.append("")

    lines.append("## 4) Покрытие данных")
    lines.append(
        md_table(
            ["Метрика", "Значение"],
            [
                ["Доменов всего", total],
                ["Успешный WHOIS (ok=True)", ok],
                ["HTTP-профиль получен (есть status_code)", http_ok],
                ["TLS сертификат получен (есть notAfter)", tls_ok],
                ["Доменов с треккерами (любые)", tracker_any],
                ["Яндекс.Метрика (ym/yaCounter)", tracker_ym],
                ["Google Analytics (UA-)", tracker_ga_ua],
                ["Google Analytics 4 (G-)", tracker_ga4],
                ["Google Tag Manager (GTM-)", tracker_gtm],
                ["Google Ads (AW-)", tracker_gads],
                ["Google Ads conversion labels", tracker_gads_labels],
                ["Facebook Pixel", tracker_fb],
                ["WHOIS org (не privacy) присутствует", whois_org_present],
                ["DNS записи", "Собраны для всех доменов (A/AAAA/MX/NS/TXT/SOA, где доступно)"],
                ["GeoIP/ASN", "Собрано по IP из A/AAAA (может отражать CDN/DDoS, не origin)"],
            ],
        )
    )
    lines.append("")

    lines.append("## 5) Методика связей (аффилированность)")
    lines.append(
        "\n".join(
            [
                "Связи анализировались по слоям (чем ниже слой, тем чаще это **общий провайдер**, а не общий владелец):",
                "",
                "- **WHOIS**: совпадения `whois_org` (если не скрыто приватностью), косвенно — email-домены контактов.",
                "- **DNS**: общие `NS`/`SOA`/`MX`/`TXT`. Одинаковые NS часто = общий сервис DNS, но иногда = единая админка.",
                "- **IP / ASN / Geo**: общие IP/ASN/локации. При **CDN/DDoS** (Cloudflare/DDOS-GUARD/Qrator) IP обычно не origin.",
                "- **HTTP**: общий redirect target, одинаковый final host, схожие server/title — сильные операционные признаки.",
                "- **Треккеры/аналитика**: общие публичные ID (YM/GA/GA4/GTM/AW/FB Pixel). Часто = общая инфраструктура/маркетинг.",
                "- **TLS**: issuer/subject/SAN. В этом наборе данных не найдено общих серийных номеров сертификатов.",
            ]
        )
    )
    lines.append("")

    # 3) Distributions
    lines.append("## 6) Сводные распределения")

    country_counter = Counter()
    for d in domains:
        info = infos[d]
        primary_ip = info.ips[0] if info.ips else ""
        c = info.ip_country.get(primary_ip, "")
        if c:
            country_counter[c] += 1
    lines.append("### 6.1 География (по первому IP из A/AAAA)")
    lines.append(md_table(["Страна", "Доменов"], [[c, n] for c, n in country_counter.most_common(25)]))
    lines.append("")

    as_counter = Counter()
    for d in domains:
        as_set = {a for a in infos[d].ip_as.values() if a}
        for a in as_set:
            as_counter[a] += 1
    lines.append("### 6.2 ASN / провайдер (по уникальным доменам)")
    lines.append(md_table(["ASN", "Доменов"], [[a, n] for a, n in as_counter.most_common(30)]))
    lines.append("")

    ns_counter = Counter()
    for d in domains:
        for p in infos[d].ns_providers:
            ns_counter[p] += 1
    lines.append("### 6.3 DNS-провайдеры (по NS base-domain)")
    lines.append(md_table(["NS provider", "Доменов"], [[p, n] for p, n in ns_counter.most_common(30)]))
    lines.append("")

    mx_counter = Counter()
    for d in domains:
        for p in infos[d].mx_providers:
            mx_counter[p] += 1
    lines.append("### 6.4 Почтовая инфраструктура (по MX base-domain)")
    lines.append(md_table(["MX provider", "Доменов"], [[p, n] for p, n in mx_counter.most_common(30)]))
    lines.append("")

    code_counter = Counter()
    for d in domains:
        code = infos[d].http_status_code
        if code is not None:
            code_counter[code] += 1
    lines.append("### 6.5 HTTP коды ответа (по конечному URL)")
    lines.append(md_table(["HTTP status", "Доменов"], [[code, n] for code, n in code_counter.most_common()]))
    lines.append("")

    issuer_counter = Counter()
    for d in domains:
        iss = infos[d].tls_issuer_cn
        if iss:
            issuer_counter[iss] += 1
    lines.append("### 6.6 TLS issuer (CN)")
    lines.append(md_table(["Issuer CN", "Доменов"], [[iss, n] for iss, n in issuer_counter.most_common(25)]))
    lines.append("")

    front_counter = Counter()
    for d in domains:
        classes = {asn_class(a) for a in infos[d].ip_as.values() if a}
        if "cdn" in classes:
            front_counter["CDN (например Cloudflare)"] += 1
        elif "ddos" in classes or (infos[d].http_server or "").lower() in {"ddos-guard", "qrator"}:
            front_counter["DDoS/WAF (например DDOS-GUARD/Qrator)"] += 1
        else:
            front_counter["Прямой хостинг (без CDN/DDoS по A/AAAA)"] += 1
    lines.append("### 6.7 Признаки CDN/DDoS (по ASN/Server)")
    lines.append(md_table(["Класс", "Доменов"], [[k, v] for k, v in front_counter.most_common()]))
    lines.append("")

    lines.append("### 6.8 Треккеры: покрытие по типам")
    lines.append(
        md_table(
            ["Тип", "Доменов"],
            [
                ["Яндекс.Метрика", tracker_ym],
                ["GA (UA-)", tracker_ga_ua],
                ["GA4 (G-)", tracker_ga4],
                ["GTM", tracker_gtm],
                ["Google Ads (AW-)", tracker_gads],
                ["Google Ads conversion label", tracker_gads_labels],
                ["Facebook Pixel", tracker_fb],
            ],
        )
    )
    lines.append("")

    lines.append("### 6.9 Треккеры: топ ID по числу доменов")
    tracker_sections = [
        ("Яндекс.Метрика", tracker_ym_counter),
        ("Google Analytics (UA-)", tracker_ga_ua_counter),
        ("Google Analytics 4 (G-)", tracker_ga4_counter),
        ("Google Tag Manager", tracker_gtm_counter),
        ("Google Ads (AW-)", tracker_gads_counter),
        ("Google Ads conversion labels", tracker_gads_label_counter),
        ("Facebook Pixel", tracker_fb_counter),
    ]
    for idx, (label, counter) in enumerate(tracker_sections, start=1):
        lines.append(f"#### 6.9.{idx} {label}")
        if counter:
            rows = [[tid, n] for tid, n in counter.most_common(15)]
            lines.append(md_table(["ID", "Доменов"], rows))
        else:
            lines.append("_Не найдено._")
        lines.append("")

    cdn_domains = [
        d for d in domains if "cdn" in {asn_class(a) for a in infos[d].ip_as.values() if a}
    ]
    ddos_domains = [
        d
        for d in domains
        if "ddos" in {asn_class(a) for a in infos[d].ip_as.values() if a}
        or (infos[d].http_server or "").lower() in {"ddos-guard", "qrator"}
    ]

    redirects_count = sum(1 for d in domains if infos[d].http_final_host and infos[d].http_final_host != d)

    # 6.10 Key observations (auto)
    lines.append("### 6.10 Ключевые наблюдения")
    top_asn = as_counter.most_common(1)[0] if as_counter else ("", 0)
    top_ns = ns_counter.most_common(1)[0] if ns_counter else ("", 0)
    top_mx = mx_counter.most_common(1)[0] if mx_counter else ("", 0)
    lines.append(
        "\n".join(
            [
                f"- CDN по IP/ASN: `{len(cdn_domains)}/{total}` доменов",
                f"- DDoS/WAF по IP/ASN/Server: `{len(ddos_domains)}/{total}` доменов",
                f"- Редирект на другой host: `{redirects_count}/{total}` доменов",
                f"- Доменов с треккерами: `{tracker_any}/{total}`",
                f"- Топ ASN: `{top_asn[0]}` (доменов: {top_asn[1]})",
                f"- Топ NS provider: `{top_ns[0]}` (доменов: {top_ns[1]})",
                f"- Топ MX provider: `{top_mx[0]}` (доменов: {top_mx[1]})",
            ]
        )
    )
    lines.append("")

    # 7) Direct links
    lines.append("## 7) Прямые связи по индикаторам")

    ip_to_domains: Dict[str, List[str]] = defaultdict(list)
    ip_to_as: Dict[str, str] = {}
    for d in domains:
        info = infos[d]
        for ip in info.ips:
            ip_to_domains[ip].append(d)
            ip_to_as[ip] = info.ip_as.get(ip, "")
    for ip in list(ip_to_domains.keys()):
        ip_to_domains[ip] = sorted(set(ip_to_domains[ip]))

    non_cdn_shared = []
    for ip, ds in ip_to_domains.items():
        if len(ds) < 2:
            continue
        if asn_class(ip_to_as.get(ip, "")) != "host":
            continue
        non_cdn_shared.append((ip, len(ds), ip_to_as.get(ip, ""), ds))
    non_cdn_shared.sort(key=lambda x: (-x[1], x[0]))

    lines.append("### 7.1 Общие origin-IP (без CDN/DDoS по ASN)")
    if non_cdn_shared:
        rows = []
        for ip, cnt, as_str, ds in non_cdn_shared[:30]:
            rows.append([ip, cnt, as_str, fmt_list(ds, max_items=12)])
        lines.append(md_table(["IP", "Доменов", "ASN", "Домены"], rows))
        if len(non_cdn_shared) > 30:
            lines.append("")
            lines.append(f"_Показаны топ-30 из {len(non_cdn_shared)} общих origin-IP._")
    else:
        lines.append("_Общих origin-IP не найдено._")
    lines.append("")

    # Identical IP sets
    ipset_groups: Dict[Tuple[str, ...], List[str]] = defaultdict(list)
    for d in domains:
        ips = tuple(sorted(set(infos[d].ips)))
        if ips:
            ipset_groups[ips].append(d)
    identical = [(ips, sorted(ds)) for ips, ds in ipset_groups.items() if len(ds) > 1]
    identical.sort(key=lambda x: (-len(x[1]), len(x[0]), x[1][0]))
    lines.append("### 7.2 Полностью совпадающие наборы IP (A/AAAA)")
    if identical:
        rows = []
        for ips, ds in identical[:25]:
            as_classes = sorted({asn_class(ip_to_as.get(ip, "")) for ip in ips})
            rows.append([len(ds), fmt_list(list(ips), max_items=6), ",".join(as_classes), fmt_list(ds, max_items=12)])
        lines.append(md_table(["Доменов", "IP set", "ASN-class", "Домены"], rows))
        if len(identical) > 25:
            lines.append("")
            lines.append(f"_Показаны топ-25 из {len(identical)} групп._")
    else:
        lines.append("_Групп с полностью совпадающими наборами IP не найдено._")
    lines.append("")

    # Redirects to other hosts
    redirects: List[Tuple[str, str]] = []
    for d in domains:
        info = infos[d]
        if info.http_final_host and info.http_final_host != d:
            redirects.append((d, info.http_final_host))
    lines.append("### 7.3 Редиректы на другой хост (HTTP final host != domain)")
    if redirects:
        by_target = defaultdict(list)
        for src, tgt in redirects:
            by_target[tgt].append(src)
        rows = []
        for tgt, srcs in sorted(by_target.items(), key=lambda x: (-len(x[1]), x[0])):
            rows.append([tgt, len(srcs), fmt_list(sorted(srcs), max_items=20)])
        lines.append(md_table(["Target host", "Sources", "Source domains"], rows))
    else:
        lines.append("_Редиректов на другой хост не найдено._")
    lines.append("")

    # WHOIS org repeats (non-privacy)
    org_groups = group_by(
        (infos[d].whois_org, d)
        for d in domains
        if infos[d].whois_org and not infos[d].whois_org_is_privacy
    )
    org_repeated = [(org, ds) for org, ds in org_groups.items() if len(ds) > 1]
    org_repeated.sort(key=lambda x: (-len(x[1]), x[0]))
    lines.append("### 7.4 Повторяющиеся WHOIS org (не privacy)")
    if org_repeated:
        rows = [[org, len(ds), fmt_list(ds, max_items=30)] for org, ds in org_repeated]
        lines.append(md_table(["WHOIS org", "Доменов", "Домены"], rows))
    else:
        lines.append("_Повторяющихся не-privacy WHOIS org не найдено._")
    lines.append("")

    # MX non-major repeats
    mx_nonmajor_groups = defaultdict(list)
    for d in domains:
        for p in infos[d].mx_providers:
            if p and p not in MAJOR_MX_PROVIDERS:
                mx_nonmajor_groups[p].append(d)
    mx_nonmajor_repeated = [(p, sorted(set(ds))) for p, ds in mx_nonmajor_groups.items() if len(set(ds)) > 1]
    mx_nonmajor_repeated.sort(key=lambda x: (-len(x[1]), x[0]))
    lines.append("### 7.5 Повторяющиеся MX-провайдеры (не крупные публичные)")
    if mx_nonmajor_repeated:
        rows = [[p, len(ds), fmt_list(ds, max_items=30)] for p, ds in mx_nonmajor_repeated[:30]]
        lines.append(md_table(["MX base-domain", "Доменов", "Домены"], rows))
        if len(mx_nonmajor_repeated) > 30:
            lines.append("")
            lines.append(f"_Показаны топ-30 из {len(mx_nonmajor_repeated)} групп._")
    else:
        lines.append("_Повторяющихся non-major MX-провайдеров не найдено._")
    lines.append("")

    # WHOIS email-domain repeats (domain part only)
    email_dom_counter = Counter(ed for d in domains for ed in infos[d].whois_email_domains)
    lines.append("### 7.6 Повторяющиеся email-домены контактов WHOIS (без раскрытия адресов)")
    if email_dom_counter:
        lines.append(
            md_table(
                ["Email domain", "Доменов"],
                [[ed, n] for ed, n in email_dom_counter.most_common(30)],
            )
        )
        lines.append("")
        lines.append("_Важно: часто это домены регистраторов/abuse/приватности, а не владельцев сайтов._")
    else:
        lines.append("_Email контакты WHOIS не обнаружены._")
    lines.append("")

    lines.append("### 7.7 Повторяющиеся рекламные/аналитические ID")

    def append_tracker_groups(title: str, attr_name: str) -> None:
        groups = group_by((tid, d) for d in domains for tid in getattr(infos[d], attr_name))
        repeated = [(tid, ds) for tid, ds in groups.items() if len(ds) > 1]
        repeated.sort(key=lambda x: (-len(x[1]), x[0]))
        lines.append(f"**{title}**")
        if repeated:
            rows = [[tid, len(ds), fmt_list(ds, max_items=25)] for tid, ds in repeated[:25]]
            lines.append(md_table(["ID", "Доменов", "Домены"], rows))
            if len(repeated) > 25:
                lines.append("")
                lines.append(f"_Показаны топ-25 из {len(repeated)} групп._")
        else:
            lines.append("_Повторяющихся ID не найдено._")
        lines.append("")

    append_tracker_groups("Яндекс.Метрика", "tracker_ym_ids")
    append_tracker_groups("Google Analytics (UA-)", "tracker_ga_ua_ids")
    append_tracker_groups("Google Analytics 4 (G-)", "tracker_ga4_ids")
    append_tracker_groups("Google Tag Manager", "tracker_gtm_ids")
    append_tracker_groups("Google Ads (AW-)", "tracker_gads_aw_ids")
    append_tracker_groups("Google Ads conversion labels", "tracker_gads_conversion_labels")
    append_tracker_groups("Facebook Pixel", "tracker_fb_pixel_ids")

    # 8) Strongest pairs
    lines.append("## 8) Сильнейшие парные связи (top-30 по score)")
    if edges:
        top_edges = sorted(edges, key=lambda x: (-x[2], x[0], x[1]))[:30]
        rows = []
        for a, b, sc, cols in top_edges:
            reason_str = ", ".join(cols[:6])
            rows.append([sc, a, b, reason_str])
        lines.append(md_table(["Score", "A", "B", "Evidence"], rows))
    else:
        lines.append("_Парных связей по выбранному порогу не найдено._")
    lines.append("")

    # Appendices
    lines.append("## A) Инвентаризация доменов (кратко)")
    inv_rows = []
    for d in domains:
        info = infos[d]
        primary_ip = info.ips[0] if info.ips else ""
        primary_as = info.ip_as.get(primary_ip, "")
        primary_country = info.ip_country.get(primary_ip, "")
        inv_rows.append(
            [
                d,
                primary_ip,
                primary_as,
                primary_country,
                fmt_list(info.ns_providers, 2),
                fmt_list(info.mx_providers, 2),
                info.http_status_code or "",
                info.http_final_host,
            ]
        )
    lines.append(
        md_table(
            ["Domain", "Primary IP", "Primary ASN", "Country", "NS providers", "MX providers", "HTTP", "Final host"],
            inv_rows,
        )
    )
    lines.append("")

    lines.append("## B) Ограничения и рекомендации")
    lines.append(
        "\n".join(
            [
                "- **CDN/DDoS маскируют origin**: общие IP/ASN Cloudflare/DDOS-GUARD чаще отражают общий сервис, а не владельца.",
                "- **WHOIS часто редактирован**: отсутствие org/email не означает отсутствие связи.",
                "- Для доменов за Cloudflare/DDOS полезны **DNS history / пассивный DNS / CT лог** и поиск утечек origin.",
                "- **Треккеры/аналитика**: один ID может быть у сети сайтов или агентства; без исполнения JS часть тегов не видна.",
                "- Дополнительно можно связать сайты по favicon-хэшу, шаблонам CMS, JS-бандлам.",
            ]
        )
    )
    lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Markdown affiliation report from whois_sites_full.xlsx")
    parser.add_argument("--input", default=INPUT_XLSX_DEFAULT, help="Input XLSX (default: whois_sites_full.xlsx)")
    parser.add_argument("--output", default=OUTPUT_MD_DEFAULT, help="Output MD (default: domain_affiliation_report.md)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    df = pd.read_excel(input_path)
    infos = build_domain_infos(df)
    report = build_report(df, infos)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Wrote: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
