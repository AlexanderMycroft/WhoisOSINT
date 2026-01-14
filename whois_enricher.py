#!/usr/bin/env python3
"""
Скрипт для обогащения доменов полной WHOIS-информацией.

Вход: TXT (по одному домену в строке).
Выход: XLSX (1 строка = 1 домен, колонки = поля WHOIS + метаданные).
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
import re
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import pandas as pd
import requests
import whois
from dns import resolver

logger = logging.getLogger("whois_enricher")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler("whois_enricher.log", encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def normalize_cell(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple, set)):
        return json.dumps([normalize_cell(v) for v in value], ensure_ascii=False, default=_json_default)
    if isinstance(value, dict):
        return json.dumps({str(k): normalize_cell(v) for k, v in value.items()}, ensure_ascii=False, default=_json_default)
    return value


def normalize_domain(domain: str) -> Optional[str]:
    candidate = domain.strip()
    if not candidate:
        return None

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.netloc or parsed.path

    candidate = candidate.strip().lower()
    if ":" in candidate and not candidate.startswith("["):
        candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip(".")
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return None

    try:
        candidate = candidate.encode("idna").decode("ascii")
    except Exception:
        return None

    labels = candidate.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        if any(ch not in allowed for ch in label):
            return None

    return candidate


def load_domains_txt(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            domains.append(line)
    return domains


class RateLimiter:
    def __init__(self, delay_seconds: float):
        self._delay = max(0.0, float(delay_seconds))
        self._lock = Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self._delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                time.sleep(self._next_allowed - now)
            self._next_allowed = time.monotonic() + self._delay


def safe_json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=_json_default)


def build_dns_resolver(timeout_seconds: float) -> resolver.Resolver:
    res = resolver.Resolver(configure=True)
    if timeout_seconds and timeout_seconds > 0:
        res.timeout = float(timeout_seconds)
        res.lifetime = float(timeout_seconds)
    return res


def dns_query(res: resolver.Resolver, domain: str, rtype: str) -> List[str]:
    answers = res.resolve(domain, rtype, raise_on_no_answer=False)
    if not answers:
        return []
    result: List[str] = []
    for rdata in answers:
        result.append(str(rdata).strip())
    return result


def collect_dns(domain: str, dns_timeout: float) -> Dict[str, Any]:
    res = build_dns_resolver(dns_timeout)
    out: Dict[str, Any] = {}

    def q(rtype: str) -> List[str]:
        try:
            return dns_query(res, domain, rtype)
        except Exception as e:
            out[f"dns_{rtype}_error"] = str(e)
            return []

    out["dns_A"] = q("A")
    out["dns_AAAA"] = q("AAAA")
    out["dns_CNAME"] = q("CNAME")
    out["dns_MX"] = q("MX")
    out["dns_NS"] = q("NS")
    out["dns_TXT"] = q("TXT")
    out["dns_SOA"] = q("SOA")
    return out


def collect_reverse_dns(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def tls_cert_info(host: str, timeout_seconds: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout_seconds) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {}
                out["tls_subject"] = cert.get("subject")
                out["tls_issuer"] = cert.get("issuer")
                out["tls_version"] = ssock.version()
                out["tls_notBefore"] = cert.get("notBefore")
                out["tls_notAfter"] = cert.get("notAfter")
                out["tls_serialNumber"] = cert.get("serialNumber")
                out["tls_subjectAltName"] = cert.get("subjectAltName")
                return out
    except Exception as e:
        out["tls_error"] = str(e)
        return out


def _extract_html_title(html: str) -> Optional[str]:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:300] if title else None


SCRIPT_SRC_RE = re.compile(r"(?is)<script[^>]+?\bsrc\s*=\s*(['\"]?)([^\"'>\s]+)\1")
YM_INIT_RE = re.compile(r"\bym\(\s*['\"]?(\d{3,})['\"]?\s*,\s*['\"]init['\"]", re.I)
YA_COUNTER_RE = re.compile(r"\byaCounter(\d{3,})\b", re.I)
GA_UA_RE = re.compile(r"\bUA-\d{4,10}-\d+\b", re.I)
GA4_RE = re.compile(r"\bG-[A-Z0-9]{6,12}\b", re.I)
GTM_RE = re.compile(r"\bGTM-[A-Z0-9]{4,10}\b", re.I)
AW_ID_RE = re.compile(r"\bAW-\d{5,12}\b", re.I)
AW_CONV_RE = re.compile(r"\bAW-(\d{5,12})/([A-Za-z0-9_-]{3,})\b", re.I)
FBQ_INIT_RE = re.compile(r"\bfbq\(\s*['\"]init['\"]\s*,\s*['\"]?(\d{5,20})['\"]?", re.I)


def _new_tracker_buckets() -> Dict[str, set]:
    return {
        "ym_ids": set(),
        "ga_ua_ids": set(),
        "ga4_ids": set(),
        "gads_aw_ids": set(),
        "gads_conv_labels": set(),
        "gtm_ids": set(),
        "fb_pixel_ids": set(),
    }


def _merge_tracker_buckets(target: Dict[str, set], incoming: Dict[str, set]) -> None:
    for key, values in incoming.items():
        target[key].update(values)


def extract_trackers_from_text(text: str) -> Dict[str, set]:
    buckets = _new_tracker_buckets()
    if not text:
        return buckets

    for m in YM_INIT_RE.finditer(text):
        buckets["ym_ids"].add(m.group(1))
    for m in YA_COUNTER_RE.finditer(text):
        buckets["ym_ids"].add(m.group(1))

    for m in GA_UA_RE.finditer(text):
        buckets["ga_ua_ids"].add(m.group(0).upper())
    for m in GA4_RE.finditer(text):
        buckets["ga4_ids"].add(m.group(0).upper())

    for m in GTM_RE.finditer(text):
        buckets["gtm_ids"].add(m.group(0).upper())

    for m in AW_ID_RE.finditer(text):
        buckets["gads_aw_ids"].add(f"AW-{m.group(0).split('-', 1)[1]}")
    for m in AW_CONV_RE.finditer(text):
        aw_id = f"AW-{m.group(1)}"
        label = m.group(2)
        buckets["gads_aw_ids"].add(aw_id)
        buckets["gads_conv_labels"].add(f"{aw_id}/{label}")

    for m in FBQ_INIT_RE.finditer(text):
        buckets["fb_pixel_ids"].add(m.group(1))

    return buckets


def extract_script_srcs(html: str) -> List[str]:
    if not html:
        return []
    return [m.group(2).strip() for m in SCRIPT_SRC_RE.finditer(html) if m.group(2).strip()]


def normalize_js_url(src: str, base_url: str) -> Optional[str]:
    raw = (src or "").strip()
    if not raw:
        return None
    if raw.startswith(("data:", "javascript:", "blob:")):
        return None
    url = urljoin(base_url, raw)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    return url


def fetch_text_limited(
    session: requests.Session,
    url: str,
    timeout_seconds: float,
    max_bytes: int,
) -> Optional[str]:
    resp: Optional[requests.Response] = None
    try:
        resp = session.get(url, timeout=timeout_seconds, allow_redirects=True, stream=True)
        content = resp.raw.read(max_bytes, decode_content=True)
        if isinstance(content, bytes):
            encoding = resp.encoding or "utf-8"
            return content.decode(encoding, errors="replace")
        return str(content)
    except Exception:
        return None
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def empty_tracker_payload() -> Dict[str, str]:
    return {
        "trackers_ym_ids": safe_json_dumps([]),
        "trackers_ga_ua_ids": safe_json_dumps([]),
        "trackers_ga4_ids": safe_json_dumps([]),
        "trackers_gads_aw_ids": safe_json_dumps([]),
        "trackers_gads_conversion_labels": safe_json_dumps([]),
        "trackers_gtm_ids": safe_json_dumps([]),
        "trackers_fb_pixel_ids": safe_json_dumps([]),
    }


def collect_trackers(
    html: str,
    base_url: str,
    session: requests.Session,
    timeout_seconds: float,
    max_js_files: int,
    max_js_bytes: int,
) -> Dict[str, str]:
    buckets = extract_trackers_from_text(html)
    script_srcs = extract_script_srcs(html)
    seen_urls: set = set()
    js_urls: List[str] = []

    for src in script_srcs:
        url = normalize_js_url(src, base_url)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        js_urls.append(url)
        _merge_tracker_buckets(buckets, extract_trackers_from_text(url))
        if max_js_files and len(js_urls) >= max_js_files:
            break

    if max_js_files:
        for url in js_urls:
            js_text = fetch_text_limited(session, url, timeout_seconds, max_js_bytes)
            if js_text:
                _merge_tracker_buckets(buckets, extract_trackers_from_text(js_text))

    return {
        "trackers_ym_ids": safe_json_dumps(sorted(buckets["ym_ids"])),
        "trackers_ga_ua_ids": safe_json_dumps(sorted(buckets["ga_ua_ids"])),
        "trackers_ga4_ids": safe_json_dumps(sorted(buckets["ga4_ids"])),
        "trackers_gads_aw_ids": safe_json_dumps(sorted(buckets["gads_aw_ids"])),
        "trackers_gads_conversion_labels": safe_json_dumps(sorted(buckets["gads_conv_labels"])),
        "trackers_gtm_ids": safe_json_dumps(sorted(buckets["gtm_ids"])),
        "trackers_fb_pixel_ids": safe_json_dumps(sorted(buckets["fb_pixel_ids"])),
    }


def http_probe(
    host: str,
    timeout_seconds: float,
    user_agent: str,
    trackers_max_js: int,
    trackers_max_bytes: int,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out.update(empty_tracker_payload())
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    def try_url(url: str) -> Optional[requests.Response]:
        try:
            resp = session.get(url, timeout=timeout_seconds, allow_redirects=True, stream=True)
            return resp
        except Exception as e:
            out[f"http_error_{urlparse(url).scheme}"] = str(e)
            return None

    resp = try_url(f"https://{host}/")
    if resp is None:
        resp = try_url(f"http://{host}/")
    if resp is None:
        return out

    out["http_final_url"] = resp.url
    out["http_status_code"] = resp.status_code
    out["http_history"] = [r.url for r in resp.history]
    out["http_headers"] = dict(resp.headers)
    out["http_server"] = resp.headers.get("Server")
    out["http_content_type"] = resp.headers.get("Content-Type")

    try:
        content = resp.raw.read(256_000, decode_content=True)
        if isinstance(content, bytes):
            encoding = resp.encoding or "utf-8"
            html = content.decode(encoding, errors="replace")
        else:
            html = str(content)
        out["http_title"] = _extract_html_title(html)
        out.update(
            collect_trackers(
                html,
                resp.url,
                session,
                timeout_seconds,
                max(0, int(trackers_max_js)),
                max(0, int(trackers_max_bytes)),
            )
        )
    except Exception as e:
        out["http_body_error"] = str(e)
    finally:
        try:
            resp.close()
        except Exception:
            pass
        session.close()

    return out


class GeoIpClient:
    def __init__(self, delay_seconds: float = 1.0):
        self._limiter = RateLimiter(delay_seconds)
        self._lock = Lock()
        self._cache: Dict[str, Dict[str, Any]] = {}

    def lookup(self, ip: str, timeout_seconds: float) -> Dict[str, Any]:
        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached

        self._limiter.wait()
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"},
                timeout=timeout_seconds,
            )
            data = resp.json() if resp.content else {}
        except Exception as e:
            data = {"status": "fail", "message": str(e), "query": ip}

        with self._lock:
            self._cache[ip] = data
        return data


def whois_to_row(domain: str, record: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {"domain": domain}

    if isinstance(record, dict):
        items = record.items()
    else:
        try:
            items = dict(record).items()
        except Exception:
            items = []

    for key, value in items:
        row[f"whois_{key}"] = normalize_cell(value)

    raw_value = None
    if isinstance(record, dict):
        raw_value = record.get("raw")
    else:
        raw_value = getattr(record, "raw", None)
        if raw_value is None:
            raw_value = getattr(record, "text", None)

    if raw_value is not None:
        if isinstance(raw_value, (list, tuple)):
            row["whois_raw"] = "\n".join(str(v) for v in raw_value if v is not None)
        else:
            row["whois_raw"] = str(raw_value)

    return row


def enrich_one(domain_input: str, timeout_seconds: float, rate_limiter: RateLimiter) -> Dict[str, Any]:
    started_at = time.time()
    normalized = normalize_domain(domain_input)

    row: Dict[str, Any] = {
        "domain_input": domain_input,
        "domain": normalized or "",
        "query_time": datetime.now().isoformat(),
        "ok": False,
        "error": None,
        "elapsed_seconds": None,
    }

    if not normalized:
        row["error"] = "invalid_domain"
        row["elapsed_seconds"] = round(time.time() - started_at, 3)
        return row

    try:
        socket.setdefaulttimeout(timeout_seconds if timeout_seconds > 0 else None)

        rate_limiter.wait()
        record = whois.whois(normalized)
        row.update(whois_to_row(normalized, record))

        row["ok"] = True
        return row
    except Exception as e:
        row["error"] = str(e)
        return row
    finally:
        row["elapsed_seconds"] = round(time.time() - started_at, 3)


def write_xlsx(rows: List[Dict[str, Any]], output_path: str) -> None:
    df = pd.DataFrame(rows)
    df.to_excel(output_path, index=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Обогащение доменов WHOIS (TXT → XLSX).")
    parser.add_argument("input_file", help="TXT файл с доменами (по одному домену в строке)")
    parser.add_argument("-o", "--output", default="whois_results.xlsx", help="Выходной XLSX файл")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Количество потоков (по умолчанию: 5)")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Глобальная задержка между WHOIS-запросами, сек")
    parser.add_argument("-t", "--timeout", type=float, default=25.0, help="Таймаут WHOIS-запроса, сек")
    parser.add_argument("--dns-timeout", type=float, default=8.0, help="Таймаут DNS-запросов, сек")
    parser.add_argument("--http-timeout", type=float, default=12.0, help="Таймаут HTTP-запросов, сек")
    parser.add_argument("--geo-timeout", type=float, default=6.0, help="Таймаут GeoIP-запросов, сек")
    parser.add_argument("--geo-delay", type=float, default=1.0, help="Задержка между GeoIP-запросами, сек")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (compatible; whois-enricher/1.0)", help="User-Agent для HTTP")
    parser.add_argument("--trackers-max-js", type=int, default=12, help="Макс. число JS-файлов для поиска треккеров")
    parser.add_argument("--trackers-max-bytes", type=int, default=262144, help="Макс. размер JS для анализа, байт")
    parser.add_argument("-v", "--verbose", action="store_true", help="Более подробные логи")
    args = parser.parse_args()

    setup_logging(args.verbose)

    if not args.input_file.lower().endswith(".txt"):
        logger.error("Ожидается TXT файл на входе.")
        return 2

    try:
        domains_input = load_domains_txt(args.input_file)
    except Exception as e:
        logger.error(f"Не удалось прочитать файл {args.input_file}: {e}")
        return 2

    if not domains_input:
        logger.error("Входной файл пуст.")
        return 2

    workers = max(1, int(args.workers))
    rate_limiter = RateLimiter(args.delay)
    geo = GeoIpClient(delay_seconds=args.geo_delay)

    logger.info(f"Домены: {len(domains_input)}; workers={workers}; delay={args.delay}s; timeout={args.timeout}s")

    rows_by_index: Dict[int, Dict[str, Any]] = {}
    started = time.time()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        def job(domain: str) -> Dict[str, Any]:
            row = enrich_one(domain, args.timeout, rate_limiter)
            normalized = row.get("domain") or ""
            if not normalized:
                return row

            dns_data = collect_dns(normalized, args.dns_timeout)
            row["dns_A"] = safe_json_dumps(dns_data.get("dns_A", []))
            row["dns_AAAA"] = safe_json_dumps(dns_data.get("dns_AAAA", []))
            row["dns_CNAME"] = safe_json_dumps(dns_data.get("dns_CNAME", []))
            row["dns_MX"] = safe_json_dumps(dns_data.get("dns_MX", []))
            row["dns_NS"] = safe_json_dumps(dns_data.get("dns_NS", []))
            row["dns_TXT"] = safe_json_dumps(dns_data.get("dns_TXT", []))
            row["dns_SOA"] = safe_json_dumps(dns_data.get("dns_SOA", []))
            for k, v in dns_data.items():
                if k.endswith("_error"):
                    row[k] = v

            ips: List[str] = []
            ips.extend(dns_data.get("dns_A", []))
            ips.extend(dns_data.get("dns_AAAA", []))
            row["ip_list"] = safe_json_dumps(ips)
            row["reverse_dns"] = safe_json_dumps({ip: collect_reverse_dns(ip) for ip in ips})

            row["geoip"] = safe_json_dumps({ip: geo.lookup(ip, args.geo_timeout) for ip in ips})

            row.update(
                http_probe(
                    normalized,
                    args.http_timeout,
                    args.user_agent,
                    args.trackers_max_js,
                    args.trackers_max_bytes,
                )
            )
            row.update(tls_cert_info(normalized, args.http_timeout))
            return row

        futures = {executor.submit(job, domain): idx for idx, domain in enumerate(domains_input)}

        completed = 0
        for future in as_completed(futures):
            idx = futures[future]
            try:
                row = future.result()
            except Exception as e:
                row = {
                    "domain_input": domains_input[idx],
                    "domain": "",
                    "query_time": datetime.now().isoformat(),
                    "ok": False,
                    "error": f"worker_exception: {e}",
                    "elapsed_seconds": None,
                }

            rows_by_index[idx] = row
            completed += 1
            if completed % 10 == 0 or completed == len(domains_input):
                ok_count = sum(1 for r in rows_by_index.values() if r.get("ok"))
                logger.info(f"Готово {completed}/{len(domains_input)} (ok={ok_count})")

    rows = [rows_by_index[i] for i in range(len(domains_input)) if i in rows_by_index]

    try:
        write_xlsx(rows, args.output)
    except Exception as e:
        logger.error(f"Не удалось записать XLSX {args.output}: {e}")
        return 2

    elapsed = time.time() - started
    ok = sum(1 for r in rows if r.get("ok"))
    fail = len(rows) - ok
    logger.info(f"Готово. ok={ok}, fail={fail}, elapsed={elapsed:.1f}s. Выход: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
