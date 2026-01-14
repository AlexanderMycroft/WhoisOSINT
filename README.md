# WhoisOSINT by Compendium AC

CLI tools for enriching domains with WHOIS, DNS, HTTP, TLS, tracker, and GeoIP
data, plus a reporting tool that clusters domains based on shared indicators.

## Features

- WHOIS enrichment with raw text capture (via `python-whois`)
- DNS records collection (A, AAAA, CNAME, MX, NS, TXT, SOA)
- Reverse DNS lookup for resolved IPs
- HTTP probing with redirect history, headers, server, content-type, and page title
- TLS certificate summary (subject, issuer, SAN, validity window)
- Tracker detection in HTML and linked JS (YM, GA, GA4, GTM, Google Ads, Facebook Pixel)
- GeoIP metadata per IP (country, city, ASN, ISP) using `ip-api.com`
- Markdown report that highlights potential affiliations between domains

## Data Sources

- WHOIS: `python-whois`
- DNS: system resolvers via `dnspython`
- HTTP/TLS: `requests` + `ssl` sockets
- GeoIP: `http://ip-api.com/json/`

## Requirements

- Python 3.x
- Dependencies in `requirements.txt`

Install:

```bash
pip3 install -r requirements.txt
```

## Quick Start

Enrich domains from a TXT file and write an XLSX:

```bash
python3 whois_enricher.py domains.txt -o whois_results.xlsx
```

Generate an affiliation report from the XLSX:

```bash
python3 generate_domain_affiliation_report.py --input whois_results.xlsx --output domain_affiliation_report.md
```

## Usage

### whois_enricher.py

```bash
python3 whois_enricher.py INPUT.txt [options]
```

Options:

```
  -o, --output             Output XLSX file (default: whois_results.xlsx)
  -w, --workers            Number of worker threads (default: 5)
  -d, --delay              Global delay between WHOIS queries in seconds (default: 1.0)
  -t, --timeout            WHOIS timeout in seconds (default: 25.0)
  --dns-timeout            DNS timeout in seconds (default: 8.0)
  --http-timeout           HTTP timeout in seconds (default: 12.0)
  --geo-timeout            GeoIP timeout in seconds (default: 6.0)
  --geo-delay              Delay between GeoIP lookups in seconds (default: 1.0)
  --user-agent             User-Agent for HTTP probing
  --trackers-max-js         Max JS files to scan for trackers (default: 12)
  --trackers-max-bytes      Max bytes to read per JS file (default: 262144)
  -v, --verbose            Verbose logging
```

Input format (TXT):

```
google.com
facebook.com
amazon.com
```

Output columns (XLSX):

- `domain_input`, `domain`, `ok`, `error`, `query_time`, `elapsed_seconds`
- `whois_*` fields from `python-whois`
- `whois_raw` (raw WHOIS text, when available)
- `dns_*` records and `dns_*_error` fields
- `ip_list`, `reverse_dns`, `geoip`
- `http_*` fields (status, headers, final URL, title, etc.)
- `tls_*` fields (subject, issuer, SAN, dates, version)
- `trackers_*` fields with detected tracker IDs

Logging:

- Writes `whois_enricher.log` in the working directory.

### generate_domain_affiliation_report.py

Builds a Markdown report that clusters domains using shared WHOIS/DNS/HTTP/TLS/
tracker signals. The report avoids raw WHOIS text and direct PII.

```bash
python3 generate_domain_affiliation_report.py --input INPUT.xlsx --output OUTPUT.md
```

Defaults:

- Input: `whois_sites_full.xlsx`
- Output: `domain_affiliation_report.md`

## Performance and Tuning

- Use `--delay` and lower `--workers` to avoid WHOIS rate limits.
- Increase timeouts for slow resolvers or endpoints.
- Tracker extraction is limited by `--trackers-max-js` and `--trackers-max-bytes`.

## Notes and Limitations

- WHOIS data varies by TLD and registrar. Some records are redacted or missing.
- CDN/DDoS protection often masks origin IPs. Shared IPs/ASNs can indicate a
  common provider rather than ownership.
- Tracker IDs can be shared across unrelated sites (agencies, networks, etc).
- GeoIP data is best-effort and may be inaccurate or coarse.
- Use responsibly and respect the terms of upstream services (including WHOIS
  servers and `ip-api.com`).

## Project Layout

- `whois_enricher.py` - domain enrichment (WHOIS/DNS/HTTP/TLS/GeoIP/trackers)
- `generate_domain_affiliation_report.py` - Markdown report generator
- `domains.txt` - sample input list
- `requirements.txt` - Python dependencies

## Contributing

Issues and PRs are welcome. Please include sample inputs and outputs when
reporting bugs or proposing changes.

## License

MIT. See `LICENSE`.
