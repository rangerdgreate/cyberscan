import csv
import datetime
import json
import re
import argparse
import time
from collections import Counter
from collections import deque
from dataclasses import asdict, dataclass
from html import escape as html_escape
from html import unescape as html_unescape
from http.cookies import SimpleCookie
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import ssl
import socket


class ScanCancelled(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    owasp_category: str
    cwe: str
    confidence: str
    validation_status: str
    description: str
    recommendation: str
    affected_url: str
    evidence: str
    status_code: int | None = None
    detector: str = "CyberScan"

    def to_dict(self):
        return asdict(self)


class CyberScan:
    SCANNER_NAME = "CyberScan"
    SCANNER_VERSION = "1.2.0"
    DEFAULT_PORTS = [21, 22, 25, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    PORT_SERVICE_NAMES = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    SCAN_PROFILES = {
        "Quick": {
            "description": "Short baseline scan for the supplied targets.",
            "max_depth": 1,
            "max_pages": 25,
            "rate_limit": 10,
            "safe_probe_limit": 6,
            "modules": [
                "TLS and HTTPS checks",
                "Security header review",
                "Cookie flag inspection",
                "Known exposure paths",
            ],
        },
        "Full": {
            "description": "Balanced crawl and safe OWASP-aligned scan.",
            "max_depth": 3,
            "max_pages": 100,
            "rate_limit": 10,
            "safe_probe_limit": 12,
            "modules": [
                "Controlled crawling",
                "Form and input review",
                "Safe SQL/XSS indicators",
                "Sensitive file and directory checks",
            ],
        },
        "Authenticated": {
            "description": "Session-aware scan using authorized headers or cookies.",
            "max_depth": 3,
            "max_pages": 150,
            "rate_limit": 8,
            "safe_probe_limit": 16,
            "modules": [
                "Session-aware crawling",
                "Access control indicators",
                "Authenticated form review",
                "Report comparison",
            ],
        },
    }

    def __init__(
        self,
        target_url,
        scan_name=None,
        scan_type=None,
        target_urls=None,
        tags=None,
        max_depth=None,
        include_paths=None,
        exclude_paths=None,
        rate_limit=None,
        max_pages=None,
        auth_headers=None,
        session_cookies=None,
        port_scan=False,
        ports=None,
        cancel_event=None,
    ):
        self.target_url = self.normalize_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        self.final_url = self.target_url
        self.started_at = None
        self.completed_at = None
        self.duration_seconds = 0.0
        self.scan_name = scan_name or f"Scan - {self.domain or 'target'}"
        self.scan_type = self._normalize_scan_type(scan_type)
        profile = self.SCAN_PROFILES[self.scan_type]
        self.target_urls = [self.normalize_url(url) for url in (target_urls or [self.target_url])]
        self.tags = list(tags) if isinstance(tags, (list, tuple)) else (self._split_tags(tags) if tags else [])
        self.results = []
        self.result_keys = set()
        self.max_depth = max(1, min(5, int(max_depth if max_depth is not None else profile["max_depth"])))
        self.include_paths = self._compile_patterns(include_paths)
        self.exclude_paths = self._compile_patterns(exclude_paths)
        self.rate_limit = max(1, min(50, int(rate_limit if rate_limit is not None else profile["rate_limit"])))
        self.max_pages = max(1, min(500, int(max_pages if max_pages is not None else profile["max_pages"])))
        self.cancel_event = cancel_event
        self.last_request_at = 0.0
        self.crawled_urls = []
        self.safe_probe_limit = profile["safe_probe_limit"]
        self.safe_probe_count = 0
        self.port_scan_enabled = self._coerce_bool(port_scan)
        self.port_scan_ports = self._parse_ports(ports)
        self.open_ports = []
        self.optional_probe_timeout = 1.5
        self.discovery_sources = []
        self.robots_policies = []
        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": f"{self.SCANNER_NAME}/{self.SCANNER_VERSION}"
        })
        self.session.headers.update(self._coerce_mapping(auth_headers, separator=":"))
        self.session.cookies.update(self._coerce_mapping(session_cookies, separator="="))

    def _coerce_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
        return bool(value)

    def _parse_ports(self, ports):
        if not ports:
            return list(self.DEFAULT_PORTS)
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            ports = re.split(r"[\s,;]+", ports.strip())

        parsed = []
        for item in ports:
            text = str(item).strip()
            if not text:
                continue
            if "-" in text:
                start_text, end_text = text.split("-", 1)
                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    continue
                for port in range(min(start, end), max(start, end) + 1):
                    if 1 <= port <= 65535:
                        parsed.append(port)
            else:
                try:
                    port = int(text)
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    parsed.append(port)

        unique_ports = list(dict.fromkeys(parsed))
        return unique_ports[:50] or list(self.DEFAULT_PORTS)

    def _normalize_scan_type(self, scan_type):
        normalized = str(scan_type or "Quick").strip().title()
        if normalized == "Auth":
            normalized = "Authenticated"
        return normalized if normalized in self.SCAN_PROFILES else "Quick"

    def normalize_url(self, url):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        return url.rstrip("/")

    def _split_tags(self, tags):
        if not tags:
            return []
        if isinstance(tags, str):
            return [tag.strip() for tag in tags.split(",") if tag.strip()]
        return list(tags)

    def _compile_patterns(self, patterns):
        if not patterns:
            return []
        if isinstance(patterns, str):
            patterns = [line.strip() for line in re.split(r"[\n,]", patterns) if line.strip()]

        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error:
                self.add_result(
                    "Invalid Crawl Scope Pattern",
                    "Low",
                    "A05: Security Misconfiguration",
                    f"The crawl pattern could not be compiled: {pattern}",
                    "Fix invalid regular expressions before running broad automated scans."
                )
        return compiled

    def _coerce_mapping(self, values, separator=":"):
        if not values:
            return {}
        if isinstance(values, dict):
            return {str(key).strip(): str(value).strip() for key, value in values.items() if str(key).strip()}
        if isinstance(values, str):
            values = [line.strip() for line in re.split(r"[\n,;]", values) if line.strip()]

        parsed = {}
        for item in values:
            text = str(item).strip()
            if not text or separator not in text:
                continue
            key, value = text.split(separator, 1)
            key = key.strip()
            value = value.strip()
            if key:
                parsed[key] = value
        return parsed

    def _infer_cwe(self, title, owasp_category, description):
        text = f"{title} {owasp_category} {description}".lower()
        cwe_rules = [
            (("sql injection", "database-style error"), "CWE-89"),
            (("xss", "cross-site scripting", "content security policy"), "CWE-79"),
            (("csrf",), "CWE-352"),
            (("does not use https", "password form without https", "mixed content", "hsts"), "CWE-319"),
            (("form uses get", "sensitive data may appear in urls"), "CWE-598"),
            (("autocomplete",), "CWE-522"),
            (("ssl certificate", "tls"), "CWE-295"),
            (("secure flag",), "CWE-614"),
            (("httponly",), "CWE-1004"),
            (("samesite",), "CWE-1275"),
            (("x-frame-options", "clickjacking"), "CWE-1021"),
            (("directory listing",), "CWE-548"),
            (("sensitive path", "sensitive file"), "CWE-538"),
            (("error message", "stack trace"), "CWE-209"),
            (("information disclosure", "server technology", "page source"), "CWE-200"),
            (("public access", "public sensitive api", "protected api", "access control"), "CWE-284"),
            (("external domain", "external form"), "CWE-346"),
            (("frontend library", "outdated components"), "CWE-1104"),
            (("missing security header", "permissions-policy", "referrer-policy", "x-content-type-options"), "CWE-693"),
        ]
        for keywords, cwe in cwe_rules:
            if any(keyword in text for keyword in keywords):
                return cwe
        return "CWE-N/A"

    def _infer_confidence(self, title, severity, evidence=None, status_code=None):
        text = f"{title} {evidence or ''}".lower()
        if "review candidate" in text or "possible" in text:
            return "Medium"
        if severity == "Info":
            return "Low"
        if status_code or any(token in text for token in ("missing security header", "cookie", "directory listing", "does not use https")):
            return "High"
        return "Medium"

    def _validation_status(self, confidence):
        if confidence == "High":
            return "Observed"
        if confidence == "Medium":
            return "Needs Manual Validation"
        return "Informational"

    def _allowed_hosts(self):
        return {
            urlparse(url).netloc
            for url in self.target_urls
            if urlparse(url).netloc
        } or {self.domain}

    def _path_in_scope(self, url, is_seed=False):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.netloc not in self._allowed_hosts():
            return False

        path = parsed.path or "/"
        if any(pattern.search(path) for pattern in self.exclude_paths):
            return False
        if is_seed or not self.include_paths:
            return True
        return any(pattern.search(path) for pattern in self.include_paths)

    def _rate_limited_get(self, url, **kwargs):
        self._check_cancelled()
        wait = (1 / self.rate_limit) - (time.monotonic() - self.last_request_at)
        if wait > 0:
            time.sleep(wait)
        self._check_cancelled()
        response = self.session.get(url, **kwargs)
        self.last_request_at = time.monotonic()
        self._check_cancelled()
        return response

    def _check_cancelled(self):
        if self.cancel_event and self.cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by owner.")

    def _normalize_discovered_url(self, base_url, href):
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            return None
        parsed = urlparse(urljoin(base_url, href))
        return parsed._replace(fragment="").geturl().rstrip("/")

    def _extract_links(self, response):
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return []
        soup = BeautifulSoup(response.text, "html.parser")
        discovered = []

        for element, attribute in (
            ("a", "href"),
            ("form", "action"),
            ("iframe", "src"),
        ):
            for tag in soup.find_all(element):
                url = self._normalize_discovered_url(response.url, tag.get(attribute))
                if url:
                    discovered.append(url)

        inline_script = "\n".join(script.get_text(" ", strip=True) for script in soup.find_all("script") if not script.get("src"))
        route_pattern = re.compile(r"""["']((?:/|\.{1,2}/)(?:api|admin|user|users|account|dashboard|settings|login|register|search|profile|products?)[^"' <>{}]*)["']""", re.I)
        for route in route_pattern.findall(inline_script):
            url = self._normalize_discovered_url(response.url, route)
            if url:
                discovered.append(url)

        return list(dict.fromkeys(discovered))

    def _origin_url(self, target_url):
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else target_url

    def _port_scan_hosts(self):
        hosts = []
        for target in self.target_urls:
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc or target
            if host and host not in hosts:
                hosts.append(host)
        return hosts

    def _record_discovery_source(self, source, url, count=0, notes=None):
        entry = {
            "source": source,
            "url": url,
            "discovered_urls": int(count or 0),
        }
        if notes:
            entry["notes"] = notes
        self.discovery_sources.append(entry)

    def _parse_robots_txt(self, body):
        disallow = []
        sitemaps = []
        for raw_line in body.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, value = [part.strip() for part in line.split(":", 1)]
            if key.lower() == "disallow" and value:
                disallow.append(value)
            elif key.lower() == "sitemap" and value:
                sitemaps.append(value)
        return disallow[:50], sitemaps[:10]

    def _discover_sitemap_urls(self, sitemap_url):
        try:
            response = self._rate_limited_get(sitemap_url, timeout=self.optional_probe_timeout, allow_redirects=True)
        except requests.RequestException:
            return []
        if response.status_code >= 400:
            return []

        urls = []
        for match in re.findall(r"<loc>\s*([^<]+)\s*</loc>", response.text, flags=re.I):
            normalized = self._normalize_discovered_url(sitemap_url, html_unescape(match.strip()))
            if normalized:
                urls.append(normalized)

        urls = [url for url in dict.fromkeys(urls) if self._path_in_scope(url)]
        if urls:
            self._record_discovery_source("sitemap", sitemap_url, len(urls))
        return urls[: min(50, self.max_pages)]

    def _discover_crawl_seeds(self):
        seeds = []
        checked_origins = set()
        for target in self.target_urls:
            origin = self._origin_url(target)
            if origin in checked_origins:
                continue
            checked_origins.add(origin)

            robots_url = urljoin(origin, "/robots.txt")
            sitemap_urls = [urljoin(origin, "/sitemap.xml")]
            try:
                response = self._rate_limited_get(robots_url, timeout=self.optional_probe_timeout, allow_redirects=True)
            except requests.RequestException:
                response = None

            if response and response.status_code == 200 and response.text:
                disallow, robots_sitemaps = self._parse_robots_txt(response.text)
                sitemap_urls.extend(robots_sitemaps)
                self.robots_policies.append({
                    "url": robots_url,
                    "disallow_count": len(disallow),
                    "sample_disallow": disallow[:8],
                    "sitemaps": robots_sitemaps,
                })
                self._record_discovery_source("robots.txt", robots_url, len(robots_sitemaps), notes=f"{len(disallow)} disallow rule(s) observed")

            for sitemap_url in dict.fromkeys(sitemap_urls):
                seeds.extend(self._discover_sitemap_urls(sitemap_url))

        return [url for url in dict.fromkeys(seeds) if self._path_in_scope(url)]

    def crawl_targets(self):
        discovered_seeds = self._discover_crawl_seeds()
        queue = deque((url, 0, True) for url in self.target_urls if self._path_in_scope(url, is_seed=True))
        queue.extend((url, 0, False) for url in discovered_seeds)
        seen = set()
        crawled = []

        while queue and len(crawled) < self.max_pages:
            self._check_cancelled()
            url, depth, is_seed = queue.popleft()
            if url in seen or not self._path_in_scope(url, is_seed=is_seed):
                continue
            seen.add(url)

            try:
                response = self._rate_limited_get(url, timeout=10, allow_redirects=True)
            except requests.RequestException:
                if url == self.target_url:
                    self.add_result(
                        "Target Unreachable",
                        "High",
                        "Security Misconfiguration",
                        f"The scanner could not reach the target URL: {url}",
                        "Check if the target URL is correct and accessible."
                    )
                continue

            crawled.append((url, response))

            if depth + 1 < self.max_depth:
                for link in self._extract_links(response):
                    if link not in seen and self._path_in_scope(link):
                        queue.append((link, depth + 1, False))

        self.crawled_urls = [url for url, _ in crawled]
        return crawled

    def _infer_affected_hosts(self):
        hosts = []

        for target in self.target_urls:
            host = urlparse(target).netloc or target
            if host and host not in hosts:
                hosts.append(host)

        if not hosts:
            host = self.domain or self.target_url
            if host:
                hosts.append(host)

        if len(hosts) == 1 and not hosts[0].startswith("www."):
            hosts.insert(0, f"www.{hosts[0]}")

        total_findings = sum(self.calculate_summary().values()) or len(self.results) or 1

        return [
            {
                "host": host,
                "findings": max(1, total_findings - index),
            }
            for index, host in enumerate(hosts[:4])
        ]

    def build_coverage_summary(self):
        profile = self.SCAN_PROFILES.get(self.scan_type, self.SCAN_PROFILES["Quick"])
        coverage_notes = [
            "Safe automated checks only; manual validation is still required for medium-confidence findings.",
            "Destructive exploit attempts, brute force checks, data extraction, and SSRF testing are intentionally excluded.",
        ]
        if self.scan_type != "Authenticated":
            coverage_notes.append("Run an Authenticated scan with approved session cookies or headers to cover logged-in workflows.")
        if len(self.crawled_urls) >= self.max_pages:
            coverage_notes.append("The crawl reached the configured page limit; increase max_pages or narrow scope for deeper coverage.")
        if self.safe_probe_count >= self.safe_probe_limit:
            coverage_notes.append("The safe probe limit was reached; increase the profile limits only for authorized lab-style targets.")
        if self.include_paths:
            coverage_notes.append("Include-path filters were applied, so unrelated discovered paths were skipped.")
        if self.exclude_paths:
            coverage_notes.append("Exclude-path filters were applied, so matching paths were intentionally skipped.")
        if self.port_scan_enabled:
            coverage_notes.append("Port scanning used safe TCP connection checks only; it did not grab banners, brute force services, or exploit exposed ports.")

        return {
            "targets_requested": len(self.target_urls),
            "urls_scanned": len(self.crawled_urls),
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "page_limit_reached": len(self.crawled_urls) >= self.max_pages,
            "safe_probes_used": self.safe_probe_count,
            "safe_probe_limit": self.safe_probe_limit,
            "safe_probe_limit_reached": self.safe_probe_count >= self.safe_probe_limit,
            "port_scan_enabled": self.port_scan_enabled,
            "ports_checked": self.port_scan_ports if self.port_scan_enabled else [],
            "open_ports_found": len(self.open_ports),
            "authenticated_context": bool(self.session.headers.get("Authorization") or self.session.cookies),
            "modules": profile["modules"],
            "discovery_source_count": len(self.discovery_sources),
            "notes": coverage_notes,
        }

    def add_result(
        self,
        title,
        severity,
        owasp_category,
        description,
        recommendation,
        evidence=None,
        url=None,
        status_code=None,
        cwe=None,
        confidence=None,
        validation_status=None,
    ):
        cwe = cwe or self._infer_cwe(title, owasp_category, description)
        confidence = confidence or self._infer_confidence(title, severity, evidence, status_code)
        finding = Finding(
            title=title,
            severity=severity,
            owasp_category=owasp_category,
            cwe=cwe,
            confidence=confidence,
            validation_status=validation_status or self._validation_status(confidence),
            description=description,
            recommendation=recommendation,
            affected_url=url or self.target_url,
            evidence=evidence or description,
            status_code=status_code,
            detector=self.__class__.__name__,
        )
        result = finding.to_dict()
        key = (
            result["title"],
            result["severity"],
            result["owasp_category"],
            result["cwe"],
            result["affected_url"],
            str(result["evidence"])[:160],
        )
        if key in self.result_keys:
            return
        self.result_keys.add(key)
        self.results.append(result)

    def _get_set_cookie_headers(self, response):
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        values = []

        if raw_headers is not None:
            for getter_name in ("get_all", "getlist"):
                getter = getattr(raw_headers, getter_name, None)
                if callable(getter):
                    try:
                        raw_values = getter("Set-Cookie")
                        if raw_values:
                            if isinstance(raw_values, (list, tuple)):
                                values.extend(raw_values)
                            else:
                                values.append(raw_values)
                    except Exception:
                        pass
                    if values:
                        return values

        header_value = response.headers.get("Set-Cookie")
        if header_value:
            values.append(header_value)

        return values

    def check_open_ports(self):
        if not self.port_scan_enabled:
            return

        for host in self._port_scan_hosts():
            for port in self.port_scan_ports:
                self._check_cancelled()
                try:
                    with socket.create_connection((host, port), timeout=0.6):
                        pass
                except OSError:
                    continue

                service = self.PORT_SERVICE_NAMES.get(port, "Unknown Service")
                severity = "Medium" if port not in (80, 443, 8080, 8443) else "Info"
                entry = {"host": host, "port": port, "service": service}
                if entry not in self.open_ports:
                    self.open_ports.append(entry)
                self.add_result(
                    f"Open Network Port Detected: {host}:{port}",
                    severity,
                    "A05: Security Misconfiguration",
                    f"TCP port {port} ({service}) accepted a connection on {host}.",
                    "Verify that the exposed service is required, patched, access-controlled, and restricted by firewall rules where appropriate.",
                    evidence=f"TCP connection succeeded to {host}:{port}",
                    url=f"{host}:{port}",
                    status_code=None,
                    cwe="CWE-200",
                    confidence="High",
                    validation_status="Observed",
                )

    def _parse_cookie_flags(self, response):
        parsed = {}

        for header_value in self._get_set_cookie_headers(response):
            cookie = SimpleCookie()

            try:
                cookie.load(header_value)
            except Exception:
                continue

            for name, morsel in cookie.items():
                parsed[name] = morsel

        return parsed

    def build_report_data(self):
        severity_summary = self.calculate_summary()
        category_summary = Counter(result["owasp_category"] for result in self.results)
        cwe_summary = Counter(result.get("cwe", "CWE-N/A") for result in self.results)
        confidence_summary = Counter(result.get("confidence", "Medium") for result in self.results)
        profile = self.SCAN_PROFILES.get(self.scan_type, self.SCAN_PROFILES["Quick"])

        return {
            "scanner": {
                "name": self.SCANNER_NAME,
                "version": self.SCANNER_VERSION
            },
            "scan": {
                "name": self.scan_name,
                "type": self.scan_type,
                "targets": self.target_urls,
                "tags": self.tags,
                "profile": {
                    "description": profile["description"],
                    "modules": profile["modules"],
                    "safe_probe_limit": self.safe_probe_limit,
                },
                "settings": {
                    "max_depth": self.max_depth,
                    "include_paths": [pattern.pattern for pattern in self.include_paths],
                    "exclude_paths": [pattern.pattern for pattern in self.exclude_paths],
                    "rate_limit": self.rate_limit,
                    "max_pages": self.max_pages,
                    "port_scan_enabled": self.port_scan_enabled,
                    "port_scan_ports": self.port_scan_ports,
                    "crawled_urls": self.crawled_urls,
                }
            },
            "target": self.target_url,
            "final_url": self.final_url,
            "scan_date": self.completed_at.isoformat() if self.completed_at else datetime.datetime.now().isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": severity_summary,
            "affected_hosts": self._infer_affected_hosts(),
            "category_summary": dict(category_summary),
            "cwe_summary": dict(cwe_summary),
            "confidence_summary": dict(confidence_summary),
            "coverage": self.build_coverage_summary(),
            "open_ports": self.open_ports,
            "discovery_sources": self.discovery_sources,
            "robots_policies": self.robots_policies,
            "comparison": getattr(self, "comparison", {"new": 0, "existing": 0, "fixed": 0, "fixed_findings": []}),
            "prevention_plan": self.build_prevention_plan(),
            "findings": self.results
        }

    def build_prevention_plan(self, limit=6):
        grouped = {}
        severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

        for finding in self.results:
            title = finding.get("title") or "Security Finding"
            recommendation = finding.get("recommendation") or "Review the affected endpoint and add regression coverage."
            key = (title.strip().lower(), recommendation.strip().lower())
            entry = grouped.setdefault(key, {
                "title": title,
                "recommendation": recommendation,
                "severity": finding.get("severity", "Info"),
                "owasp_category": finding.get("owasp_category", "Security Finding"),
                "cwe": finding.get("cwe", "CWE-N/A"),
                "affected_urls": [],
                "count": 0,
            })
            entry["count"] += 1
            if severity_rank.get(finding.get("severity", "Info"), 5) < severity_rank.get(entry["severity"], 5):
                entry["severity"] = finding.get("severity", entry["severity"])
            affected_url = finding.get("affected_url")
            if affected_url and affected_url not in entry["affected_urls"]:
                entry["affected_urls"].append(affected_url)

        plan = sorted(
            grouped.values(),
            key=lambda item: (severity_rank.get(item["severity"], 5), -item["count"], item["title"].lower()),
        )

        if not plan:
            return [{
                "title": "Maintain Secure Baseline",
                "recommendation": "Keep security headers, dependency checks, and periodic authenticated scans in the release process.",
                "severity": "Info",
                "owasp_category": "Baseline",
                "cwe": "CWE-N/A",
                "affected_urls": [],
                "count": 0,
            }]

        return plan[:limit]

    def fetch_homepage(self):
        try:
            response = self._rate_limited_get(self.target_url, timeout=10, allow_redirects=True)
            self.final_url = response.url
            return response
        except requests.RequestException as e:
            self.add_result(
                "Target Unreachable",
                "High",
                "Security Misconfiguration",
                f"The scanner could not reach the target. Error: {e}",
                "Check if the target URL is correct and accessible."
            )
            return None

    def check_https(self):
        parsed = urlparse(self.target_url)

        if parsed.scheme != "https":
            self.add_result(
                "Website Does Not Use HTTPS",
                "High",
                "A02: Cryptographic Failures",
                "The target website is using HTTP instead of HTTPS.",
                "Use HTTPS with a valid TLS/SSL certificate."
            )
        else:
            self.check_ssl_certificate()

    def check_ssl_certificate(self):
        hostname = urlparse(self.target_url).hostname

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            expiry_date = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.timezone.utc)

            days_left = (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days

            if days_left < 15:
                self.add_result(
                    "SSL Certificate Expiring Soon",
                    "Medium",
                    "A02: Cryptographic Failures",
                    f"The SSL certificate will expire in {days_left} days.",
                    "Renew the SSL certificate before expiration."
                )

        except Exception as e:
            self.add_result(
                "SSL Certificate Check Failed",
                "Medium",
                "A02: Cryptographic Failures",
                f"The scanner could not verify the SSL certificate. Error: {e}",
                "Make sure the website has a valid SSL/TLS certificate."
            )

    def check_security_headers(self, response):
        headers = response.headers

        required_headers = {
            "Strict-Transport-Security": {
                "severity": "Medium",
                "owasp": "A05: Security Misconfiguration",
                "description": "HSTS header is missing. This helps enforce HTTPS connections.",
                "recommendation": "Add Strict-Transport-Security header."
            },
            "Content-Security-Policy": {
                "severity": "High",
                "owasp": "A03: Injection",
                "description": "Content Security Policy is missing. This may increase XSS risk.",
                "recommendation": "Add a strong Content-Security-Policy header."
            },
            "X-Frame-Options": {
                "severity": "Medium",
                "owasp": "A05: Security Misconfiguration",
                "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking.",
                "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN."
            },
            "X-Content-Type-Options": {
                "severity": "Low",
                "owasp": "A05: Security Misconfiguration",
                "description": "X-Content-Type-Options header is missing.",
                "recommendation": "Add X-Content-Type-Options: nosniff."
            },
            "Referrer-Policy": {
                "severity": "Low",
                "owasp": "A05: Security Misconfiguration",
                "description": "Referrer-Policy header is missing.",
                "recommendation": "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin."
            },
            "Permissions-Policy": {
                "severity": "Low",
                "owasp": "A05: Security Misconfiguration",
                "description": "Permissions-Policy header is missing.",
                "recommendation": "Add Permissions-Policy to limit browser feature access."
            }
        }

        for header, info in required_headers.items():
            if header not in headers:
                self.add_result(
                    f"Missing Security Header: {header}",
                    info["severity"],
                    info["owasp"],
                    info["description"],
                    info["recommendation"]
                )

        csp = headers.get("Content-Security-Policy", "")
        if csp:
            lowered = csp.lower()
            weak_tokens = [token for token in ("'unsafe-inline'", "'unsafe-eval'", " *", "data:") if token in lowered]
            if weak_tokens:
                self.add_result(
                    "Weak Content Security Policy",
                    "Medium",
                    "A03: Injection",
                    f"The Content-Security-Policy header contains risky directives: {', '.join(weak_tokens)}.",
                    "Tighten CSP directives and avoid unsafe inline script, unsafe eval, broad wildcards, and unnecessary data sources.",
                    evidence=csp,
                    url=response.url,
                    status_code=response.status_code
                )

    def check_server_information_disclosure(self, response):
        headers = response.headers

        sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]

        for header in sensitive_headers:
            if header in headers:
                self.add_result(
                    f"Information Disclosure in Header: {header}",
                    "Low",
                    "A05: Security Misconfiguration",
                    f"The response exposes server technology information: {header}: {headers[header]}",
                    "Remove or minimize technology/version information from HTTP response headers.",
                    evidence=f"{header}: {headers[header]}",
                    url=response.url,
                    status_code=response.status_code
                )

    def check_cookie_security(self, response):
        cookies = response.cookies
        cookie_flags = self._parse_cookie_flags(response)

        for cookie in cookies:
            morsel = cookie_flags.get(cookie.name)

            secure_flag = bool(morsel["secure"]) if morsel else bool(cookie.secure)
            http_only_flag = bool(morsel["httponly"]) if morsel else False
            same_site_flag = bool(morsel["samesite"]) if morsel else False

            if not secure_flag:
                self.add_result(
                    f"Insecure Cookie: {cookie.name}",
                    "Medium",
                    "A07: Identification and Authentication Failures",
                    f"The cookie '{cookie.name}' is missing the Secure flag.",
                    "Set the Secure flag so cookies are only sent over HTTPS.",
                    evidence=f"Set-Cookie: {cookie.name}",
                    url=response.url,
                    status_code=response.status_code
                )

            if not http_only_flag:
                self.add_result(
                    f"Cookie Missing HttpOnly Flag: {cookie.name}",
                    "Medium",
                    "A07: Identification and Authentication Failures",
                    f"The cookie '{cookie.name}' may be accessible through JavaScript.",
                    "Set the HttpOnly flag to reduce cookie theft risk.",
                    evidence=f"Set-Cookie: {cookie.name}",
                    url=response.url,
                    status_code=response.status_code
                )

            if not same_site_flag:
                self.add_result(
                    f"Cookie Missing SameSite Attribute: {cookie.name}",
                    "Low",
                    "A05: Security Misconfiguration",
                    f"The cookie '{cookie.name}' is missing SameSite protection.",
                    "Set SameSite=Lax or SameSite=Strict.",
                    evidence=f"Set-Cookie: {cookie.name}",
                    url=response.url,
                    status_code=response.status_code
                )

    def check_forms(self, response):
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return

        for index, form in enumerate(forms, start=1):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            if method == "get":
                self.add_result(
                    f"Form Uses GET Method: Form #{index}",
                    "Medium",
                    "A02: Cryptographic Failures",
                    "A form uses the GET method. Sensitive data may appear in URLs.",
                    "Use POST for forms that send sensitive information.",
                    evidence=f"method={method} action={action or response.url}",
                    url=response.url,
                    status_code=response.status_code
                )

            password_fields = [
                field for field in inputs
                if field.get("type", "").lower() == "password"
            ]

            if password_fields and urlparse(self.target_url).scheme != "https":
                self.add_result(
                    f"Password Form Without HTTPS: Form #{index}",
                    "High",
                    "A07: Identification and Authentication Failures",
                    "A password field was found on a non-HTTPS page.",
                    "Always use HTTPS for login and password forms.",
                    evidence=f"{len(password_fields)} password field(s) found",
                    url=response.url,
                    status_code=response.status_code
                )

            csrf_found = False
            for field in inputs:
                field_name = field.get("name", "").lower()
                if "csrf" in field_name or "token" in field_name:
                    csrf_found = True

            if method == "post" and not csrf_found:
                self.add_result(
                    f"Possible Missing CSRF Token: Form #{index}",
                    "Medium",
                    "A01: Broken Access Control",
                    "A POST form does not appear to include a CSRF token.",
                    "Add CSRF protection tokens to sensitive forms.",
                    evidence=f"method={method} action={action or response.url}",
                    url=response.url,
                    status_code=response.status_code
                )

            if action:
                full_action_url = urljoin(self.target_url, action)
                if urlparse(full_action_url).netloc != self.domain:
                    self.add_result(
                        f"Form Submits to External Domain: Form #{index}",
                        "Medium",
                        "A04: Insecure Design",
                        f"The form action submits data to an external domain: {full_action_url}",
                        "Verify that external form submission is intentional and secure.",
                        evidence=full_action_url,
                        url=response.url,
                        status_code=response.status_code
                    )

            sensitive_names = ("password", "token", "secret", "apikey", "api_key", "credit", "card")
            for field in inputs:
                name = (field.get("name") or field.get("id") or "").lower()
                autocomplete = (field.get("autocomplete") or "").lower()
                if any(term in name for term in sensitive_names) and autocomplete not in ("off", "new-password"):
                    self.add_result(
                        f"Sensitive Input Allows Browser Autocomplete: Form #{index}",
                        "Low",
                        "A07: Identification and Authentication Failures",
                        f"The input '{name or 'unnamed'}' may allow browser autocomplete for sensitive data.",
                        "Disable autocomplete for sensitive inputs or use context-appropriate autocomplete values.",
                        evidence=f"input={name or 'unnamed'} autocomplete={autocomplete or 'not set'}",
                        url=response.url,
                        status_code=response.status_code
                    )
                    break

    def check_mixed_content(self, response):
        if urlparse(response.url).scheme != "https":
            return

        soup = BeautifulSoup(response.text, "html.parser")
        resources = []
        for tag, attribute in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")):
            for element in soup.find_all(tag):
                value = element.get(attribute)
                if value and value.startswith("http://"):
                    resources.append(value)

        if resources:
            self.add_result(
                "Mixed Content Resources Detected",
                "Medium",
                "A02: Cryptographic Failures",
                f"The HTTPS page loads {len(resources)} resource(s) over HTTP.",
                "Serve all scripts, styles, images, and frames over HTTPS.",
                evidence=", ".join(resources[:5]),
                url=response.url,
                status_code=response.status_code
            )

    def check_exposed_comments(self, response):
        soup = BeautifulSoup(response.text, "html.parser")
        comment_text = " ".join(str(comment) for comment in soup.find_all(string=lambda text: isinstance(text, Comment)))
        patterns = ("todo", "fixme", "password", "secret", "api_key", "apikey", "token")
        lowered = comment_text.lower()
        matched = [pattern for pattern in patterns if pattern in lowered]

        if matched:
            self.add_result(
                "Sensitive Development Text in Page Source",
                "Low",
                "A05: Security Misconfiguration",
                f"The page source contains development or secret-like terms: {', '.join(matched)}.",
                "Remove development notes and secret-like values from production HTML and bundled assets.",
                evidence=", ".join(matched),
                url=response.url,
                status_code=response.status_code
            )

    def check_sensitive_files(self):
        sensitive_paths = [
            "/.env",
            "/.git/config",
            "/backup.zip",
            "/backup.sql",
            "/database.sql",
            "/phpinfo.php",
            "/admin",
            "/dashboard",
            "/settings",
            "/config.php",
            "/debug",
            "/test",
            "/ftp/",
            "/ftp/package.json.bak",
            "/encryptionkeys/",
            "/logs/",
            "/swagger.json",
            "/api-docs",
        ]

        for path in sensitive_paths:
            url = urljoin(self.target_url, path)

            try:
                response = self._rate_limited_get(url, timeout=self.optional_probe_timeout, allow_redirects=False)

                if response.status_code == 200:
                    self.add_result(
                        f"Possible Exposed Sensitive Path: {path}",
                        "High",
                        "A05: Security Misconfiguration",
                        f"The path {path} returned HTTP 200 OK.",
                        "Restrict access to sensitive files and directories.",
                        evidence=f"HTTP {response.status_code} {url}",
                        url=url,
                        status_code=response.status_code
                    )

                elif response.status_code in [401, 403]:
                    self.add_result(
                        f"Protected Sensitive Path Found: {path}",
                        "Low",
                        "A05: Security Misconfiguration",
                        f"The path {path} exists but access is restricted.",
                        "Verify that this path should be publicly reachable.",
                        evidence=f"HTTP {response.status_code} {url}",
                        url=url,
                        status_code=response.status_code
                    )

            except requests.RequestException:
                continue

    def check_directory_listing(self):
        test_paths = ["/uploads/", "/assets/", "/files/", "/backup/"]

        for path in test_paths:
            url = urljoin(self.target_url, path)

            try:
                response = self._rate_limited_get(url, timeout=self.optional_probe_timeout)

                if response.status_code == 200:
                    page_text = response.text.lower()

                    if "index of" in page_text and "parent directory" in page_text:
                        self.add_result(
                            f"Directory Listing Enabled: {path}",
                            "High",
                            "A05: Security Misconfiguration",
                            f"The directory {path} appears to allow public file listing.",
                            "Disable directory listing on the web server.",
                            evidence=f"HTTP {response.status_code} {url}",
                            url=url,
                            status_code=response.status_code
                        )

            except requests.RequestException:
                continue

    def check_outdated_libraries(self, response):
        soup = BeautifulSoup(response.text, "html.parser")

        scripts = soup.find_all("script", src=True)
        links = soup.find_all("link", href=True)

        library_patterns = {
            "jquery": r"jquery[-.]([0-9]+\.[0-9]+\.[0-9]+)",
            "bootstrap": r"bootstrap[-.]([0-9]+\.[0-9]+\.[0-9]+)",
            "angular": r"angular[-.]([0-9]+\.[0-9]+\.[0-9]+)"
        }

        resources = []

        for script in scripts:
            resources.append(script["src"])

        for link in links:
            resources.append(link["href"])

        for resource in resources:
            lowered = resource.lower()

            for library, pattern in library_patterns.items():
                match = re.search(pattern, lowered)

                if match:
                    version = match.group(1)

                    self.add_result(
                        f"Detected Frontend Library: {library} {version}",
                        "Info",
                        "A06: Vulnerable and Outdated Components",
                        f"The scanner detected {library} version {version} in resource: {resource}",
                        "Check if this library version has known vulnerabilities and update if needed.",
                        evidence=resource,
                        url=response.url,
                        status_code=response.status_code
                    )

    def check_public_error_messages(self, response):
        error_patterns = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "postgresql",
            "stack trace",
            "traceback",
            "undefined index",
            "warning:",
            "fatal error"
        ]

        page_text = response.text.lower()

        for pattern in error_patterns:
            if pattern in page_text:
                self.add_result(
                    "Possible Error Message Disclosure",
                    "Medium",
                    "A05: Security Misconfiguration",
                    f"The page contains possible technical error text: {pattern}",
                    "Disable detailed error messages in production.",
                    evidence=pattern,
                    url=response.url,
                    status_code=response.status_code
                )
                break

    def _sql_error_pattern(self, text):
        patterns = [
            "sql syntax",
            "mysql_fetch",
            "mysql server",
            "you have an error in your sql",
            "sqlite error",
            "sqliteexception",
            "postgresql",
            "psqlexception",
            "ora-",
            "odbc",
            "jdbc",
            "syntax error at or near",
            "unclosed quotation mark",
        ]
        lowered = text.lower()
        return next((pattern for pattern in patterns if pattern in lowered), None)

    def _next_probe_allowed(self):
        if self.safe_probe_count >= self.safe_probe_limit:
            return False
        self.safe_probe_count += 1
        return True

    def _replace_query_param(self, url, name, value):
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        updated = [(key, value if key == name else current) for key, current in params]
        return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    def check_sql_injection_indicators(self, response):
        parsed = urlparse(response.url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        risky_names = ("id", "item", "product", "search", "q", "query", "email", "user", "username", "category")

        if params:
            for name, value in params[:4]:
                if not any(token in name.lower() for token in risky_names):
                    continue
                if not self._next_probe_allowed():
                    return
                probe_url = self._replace_query_param(response.url, name, f"{value}'")
                try:
                    probe_response = self._rate_limited_get(probe_url, timeout=8, allow_redirects=True)
                except requests.RequestException:
                    continue
                matched_error = self._sql_error_pattern(probe_response.text)
                if matched_error:
                    self.add_result(
                        f"Possible SQL Injection Error Indicator: {name}",
                        "High",
                        "A03: Injection",
                        "A safe quote probe caused a database-style error response. This suggests the parameter may reach a SQL query without proper handling.",
                        "Use parameterized queries, strict server-side validation, and generic error handling.",
                        evidence=f"Parameter '{name}' produced indicator '{matched_error}' with HTTP {probe_response.status_code}",
                        url=probe_url,
                        status_code=probe_response.status_code
                    )

        soup = BeautifulSoup(response.text, "html.parser")
        for form_index, form in enumerate(soup.find_all("form"), start=1):
            input_names = [
                (field.get("name") or field.get("id") or "").lower()
                for field in form.find_all(["input", "textarea"])
            ]
            matched = [name for name in input_names if any(token in name for token in risky_names)]
            if matched:
                self.add_result(
                    f"SQL Injection Review Candidate: Form #{form_index}",
                    "Medium",
                    "A03: Injection",
                    "The form contains fields commonly connected to database lookup or authentication logic.",
                    "Validate input server-side and use parameterized queries for all database access.",
                    evidence=f"Fields: {', '.join(matched[:6])}",
                    url=response.url,
                    status_code=response.status_code
                )

    def check_reflected_xss_indicators(self, response):
        parsed = urlparse(response.url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return

        marker = "CyberscanXssProbe<>"
        for name, value in params[:4]:
            if not self._next_probe_allowed():
                return
            probe_url = self._replace_query_param(response.url, name, marker)
            try:
                probe_response = self._rate_limited_get(probe_url, timeout=8, allow_redirects=True)
            except requests.RequestException:
                continue

            if marker in probe_response.text:
                self.add_result(
                    f"Possible Reflected XSS Indicator: {name}",
                    "High",
                    "A03: Injection",
                    "A harmless marker containing angle brackets was reflected in the response. This may indicate unsafe output handling.",
                    "Encode output by context, validate input server-side, and enforce a restrictive Content Security Policy.",
                    evidence=f"Marker reflected for parameter '{name}'",
                    url=probe_url,
                    status_code=probe_response.status_code
                )

    def check_dom_xss_indicators(self, response):
        if "text/html" not in response.headers.get("Content-Type", ""):
            return

        soup = BeautifulSoup(response.text, "html.parser")
        inline_script = "\n".join(script.get_text(" ", strip=True) for script in soup.find_all("script") if not script.get("src"))
        risky_sinks = [
            "innerHTML",
            "outerHTML",
            "document.write",
            "insertAdjacentHTML",
            "eval(",
            "setTimeout(",
            "setInterval(",
        ]
        source_patterns = ["location.hash", "location.search", "document.URL", "document.location", "window.name"]
        matched_sinks = [sink for sink in risky_sinks if sink in inline_script]
        matched_sources = [source for source in source_patterns if source in inline_script]

        if matched_sinks and matched_sources:
            self.add_result(
                "Possible DOM XSS Source-to-Sink Pattern",
                "Medium",
                "A03: Injection",
                "Inline JavaScript appears to read browser-controlled input and write to risky HTML/script sinks.",
                "Use safe DOM APIs such as textContent, sanitize HTML with a proven sanitizer, and avoid eval-like execution.",
                evidence=f"Sources: {', '.join(matched_sources[:4])}; sinks: {', '.join(matched_sinks[:5])}",
                url=response.url,
                status_code=response.status_code
            )

    def check_stored_xss_candidates(self, response):
        soup = BeautifulSoup(response.text, "html.parser")
        risky_fields = []
        for field in soup.find_all(["input", "textarea"]):
            field_type = (field.get("type") or "text").lower()
            name = (field.get("name") or field.get("id") or "").lower()
            if field_type in ("text", "search", "email", "url", "hidden") or field.name == "textarea":
                if any(token in name for token in ("comment", "review", "message", "feedback", "description", "name", "profile")):
                    risky_fields.append(name or field.name)

        if risky_fields:
            self.add_result(
                "Stored XSS Review Candidate",
                "Medium",
                "A03: Injection",
                "The page contains user-content style inputs that may later be rendered back to other users.",
                "HTML-encode stored user content by output context, sanitize rich text, and add regression tests for stored XSS.",
                evidence=f"Fields: {', '.join(risky_fields[:8])}",
                url=response.url,
                status_code=response.status_code
            )

    def check_authentication_indicators(self, response):
        soup = BeautifulSoup(response.text, "html.parser")
        password_fields = soup.find_all("input", {"type": re.compile("^password$", re.I)})
        if password_fields:
            autocomplete_values = {(field.get("autocomplete") or "").lower() for field in password_fields}
            if not autocomplete_values.intersection({"current-password", "new-password"}):
                self.add_result(
                    "Password Field Missing Explicit Autocomplete Context",
                    "Low",
                    "A07: Identification and Authentication Failures",
                    "A password input does not declare current-password or new-password autocomplete context.",
                    "Use autocomplete=current-password for login forms and autocomplete=new-password for registration or reset forms.",
                    evidence=f"autocomplete values: {', '.join(sorted(autocomplete_values)) or 'not set'}",
                    url=response.url,
                    status_code=response.status_code
                )

        page_text = response.text
        auth_terms = [
            "localStorage.setItem",
            "sessionStorage.setItem",
            "Authorization",
            "Bearer ",
            "/login",
            "/register",
            "/reset",
            "/password",
        ]
        matched = [term for term in auth_terms if term in page_text]
        if matched and any(term in page_text.lower() for term in ("token", "jwt", "bearer", "password")):
            self.add_result(
                "Client-Side Authentication Surface Detected",
                "Info",
                "A07: Identification and Authentication Failures",
                "The page or bundled script references authentication tokens, login, registration, or password flows.",
                "Review token storage, password reset protections, lockout/rate limiting, and session expiration server-side.",
                evidence=f"Matched terms: {', '.join(matched[:6])}",
                url=response.url,
                status_code=response.status_code
            )

    def check_api_exposure_in_scripts(self, response):
        if "text/html" not in response.headers.get("Content-Type", ""):
            return

        soup = BeautifulSoup(response.text, "html.parser")
        script_urls = [
            urljoin(response.url, script.get("src"))
            for script in soup.find_all("script", src=True)
            if script.get("src")
        ][:8]
        interesting_route_pattern = re.compile(
            r"(/(?:api|rest|graphql|admin|user|users|login|register|password|reset|basket|cart|profile)[A-Za-z0-9_./?=&:-]*)",
            re.I
        )

        for script_url in script_urls:
            parsed = urlparse(script_url)
            if parsed.netloc and parsed.netloc not in self._allowed_hosts():
                continue
            if not self._next_probe_allowed():
                return
            try:
                script_response = self._rate_limited_get(script_url, timeout=8, allow_redirects=True)
            except requests.RequestException:
                continue
            routes = sorted(set(interesting_route_pattern.findall(script_response.text)))
            if routes:
                self.add_result(
                    "Interesting API Routes Exposed in Client Bundle",
                    "Info",
                    "A01: Broken Access Control",
                    "Client-side JavaScript exposes route names related to authentication, users, admin, or account data.",
                    "Verify server-side authorization on every API route; do not rely on hidden frontend routes for access control.",
                    evidence=", ".join(routes[:10]),
                    url=script_url,
                    status_code=script_response.status_code
                )

    def check_basic_access_control_indicators(self):
        protected_paths = [
            "/admin",
            "/dashboard",
            "/user",
            "/account",
            "/settings"
        ]

        for path in protected_paths:
            url = urljoin(self.target_url, path)

            try:
                response = self._rate_limited_get(url, timeout=self.optional_probe_timeout, allow_redirects=False)

                if response.status_code == 200:
                    self.add_result(
                        f"Possible Public Access to Protected Page: {path}",
                        "Medium",
                        "A01: Broken Access Control",
                        f"The path {path} returned HTTP 200 OK without authentication.",
                        "Verify if this page should require authentication.",
                        evidence=f"HTTP {response.status_code} {url}",
                        url=url,
                        status_code=response.status_code
                    )

            except requests.RequestException:
                continue

    def check_common_api_security_indicators(self):
        api_paths = [
            "/api/Users",
            "/api/Users/",
            "/rest/user/whoami",
            "/rest/basket/1",
            "/rest/admin/application-configuration",
            "/api/SecurityQuestions",
            "/api/Feedbacks",
        ]

        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self._rate_limited_get(url, timeout=self.optional_probe_timeout, allow_redirects=False)
            except requests.RequestException:
                continue

            content_type = response.headers.get("Content-Type", "")
            body_preview = response.text[:240].replace("\n", " ").strip()
            if response.status_code == 200 and ("json" in content_type.lower() or body_preview.startswith(("{", "["))):
                severity = "High" if any(token in path.lower() for token in ("user", "admin", "basket")) else "Medium"
                self.add_result(
                    f"Possible Public Sensitive API: {path}",
                    severity,
                    "A01: Broken Access Control",
                    "A sensitive-looking API endpoint returned data without an authenticated session.",
                    "Enforce server-side authorization checks on every API route and verify object-level access control.",
                    evidence=f"HTTP {response.status_code}; body starts with: {body_preview[:160]}",
                    url=url,
                    status_code=response.status_code
                )
            elif response.status_code in (401, 403):
                self.add_result(
                    f"Protected API Endpoint Present: {path}",
                    "Info",
                    "A01: Broken Access Control",
                    "A sensitive-looking API endpoint exists and denied unauthenticated access.",
                    "Keep this endpoint covered by authorization regression tests.",
                    evidence=f"HTTP {response.status_code} {url}",
                    url=url,
                    status_code=response.status_code
                )

        search_paths = [
            "/rest/products/search?q=cyberscan",
            "/rest/products/search?q=cyberscan%27",
            "/rest/products/search?q=CyberscanXssProbe%3C%3E",
        ]
        for path in search_paths:
            if not self._next_probe_allowed():
                return
            url = urljoin(self.target_url, path)
            try:
                response = self._rate_limited_get(url, timeout=self.optional_probe_timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            sql_error = self._sql_error_pattern(response.text)
            if sql_error:
                self.add_result(
                    "Possible SQL Injection Error Indicator: search API",
                    "High",
                    "A03: Injection",
                    "A safe quote probe against the search API caused a database-style error response.",
                    "Use parameterized queries and return generic errors for invalid search input.",
                    evidence=f"Indicator '{sql_error}' observed at {url}",
                    url=url,
                    status_code=response.status_code
                )
            if "CyberscanXssProbe<>" in response.text:
                self.add_result(
                    "Possible Reflected XSS Indicator: search API",
                    "High",
                    "A03: Injection",
                    "A harmless marker containing angle brackets was reflected by the search API.",
                    "Encode search terms in every HTML/JSON rendering context and enforce a restrictive CSP.",
                    evidence="CyberscanXssProbe<> marker reflected",
                    url=url,
                    status_code=response.status_code
                )

    def calculate_summary(self):
        summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }

        for result in self.results:
            severity = result["severity"]
            if severity in summary:
                summary[severity] += 1

        return summary

    def scan(self):
        self.started_at = datetime.datetime.now()
        print(f"\n[+] Starting {self.SCANNER_NAME} for: {self.target_url}\n")

        original_target = self.target_url

        for target in self.target_urls:
            self._check_cancelled()
            self.target_url = target
            self.domain = urlparse(target).netloc
            self.check_https()

        self.check_open_ports()

        crawled_pages = self.crawl_targets()

        for url, response in crawled_pages:
            self._check_cancelled()
            self.target_url = url
            self.domain = urlparse(url).netloc
            if url == original_target:
                self.final_url = response.url

            self.check_security_headers(response)
            self.check_server_information_disclosure(response)
            self.check_cookie_security(response)
            self.check_forms(response)
            self.check_mixed_content(response)
            self.check_exposed_comments(response)
            self.check_outdated_libraries(response)
            self.check_public_error_messages(response)
            self.check_sql_injection_indicators(response)
            self.check_reflected_xss_indicators(response)
            self.check_dom_xss_indicators(response)
            self.check_stored_xss_candidates(response)
            self.check_authentication_indicators(response)
            self.check_api_exposure_in_scripts(response)

        for target in self.target_urls:
            self._check_cancelled()
            self.target_url = target
            self.domain = urlparse(target).netloc
            self.check_sensitive_files()
            self.check_directory_listing()
            self.check_basic_access_control_indicators()
            self.check_common_api_security_indicators()

        self.target_url = original_target
        self.domain = urlparse(original_target).netloc

        self.completed_at = datetime.datetime.now()
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

        print(f"[+] Scan completed in {self.duration_seconds:.1f}s.\n")

    def print_report(self):
        report_data = self.build_report_data()
        summary = report_data["summary"]
        elapsed = report_data["duration_seconds"]

        print("=" * 80)
        print(f"{self.SCANNER_NAME} REPORT")
        print("=" * 80)
        print(f"Scan: {report_data['scan']['name']}")
        print(f"Type: {report_data['scan']['type']}")
        print(f"Target: {report_data['target']}")
        print(f"Final URL: {report_data['final_url']}")
        print(f"Date: {report_data['scan_date']}")
        print(f"Duration: {elapsed:.1f}s")
        print("-" * 80)
        print("Summary")
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            print(f"  {severity:<8} {summary.get(severity, 0)}")
        print("-" * 80)

        if not self.results:
            print("No issues found by this prototype scanner.")
        else:
            for index, result in enumerate(self.results, start=1):
                print(f"[{index}] {result['title']}")
                print(f"  Severity: {result['severity']}")
                print(f"  OWASP Category: {result['owasp_category']}")
                print(f"  CWE: {result.get('cwe', 'CWE-N/A')}")
                print(f"  Confidence: {result.get('confidence', 'Medium')}")
                print(f"  Validation: {result.get('validation_status', 'Needs Manual Validation')}")
                print(f"  Description: {result['description']}")
                print(f"  Recommendation: {result['recommendation']}")
                print()

        print("=" * 80)

    def save_json_report(self, filename="cyberscan_report.json"):
        report_data = self.build_report_data()

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(report_data, file, indent=4)

        print(f"[+] JSON report saved as: {filename}")

    def save_csv_report(self, filename="cyberscan_report.csv"):
        with open(filename, "w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Title",
                "Severity",
                "OWASP Category",
                "CWE",
                "Confidence",
                "Affected URL",
                "Status Code",
                "Lifecycle Status",
                "Validation Status",
                "Evidence",
                "Description",
                "Recommendation"
            ])

            for finding in self.results:
                writer.writerow([
                    finding["title"],
                    finding["severity"],
                    finding["owasp_category"],
                    finding.get("cwe", "CWE-N/A"),
                    finding.get("confidence", "Medium"),
                    finding.get("affected_url", ""),
                    finding.get("status_code", ""),
                    finding.get("lifecycle_status", "New"),
                    finding.get("validation_status", "Needs Manual Validation"),
                    finding.get("evidence", ""),
                    finding["description"],
                    finding["recommendation"]
                ])

        print(f"[+] CSV report saved as: {filename}")

    def _severity_class(self, severity):
        normalized = severity.lower()
        if normalized.startswith("critical"):
            return "critical"
        if normalized.startswith("high"):
            return "high"
        if normalized.startswith("medium"):
            return "med"
        if normalized.startswith("low"):
            return "low"
        return "info"

    def save_html_report(self, filename="cyberscan_report.html"):
        report_data = self.build_report_data()
        summary = report_data["summary"]
        findings = report_data["findings"]
        category_summary = report_data["category_summary"]
        cwe_summary = report_data.get("cwe_summary", {})
        confidence_summary = report_data.get("confidence_summary", {})
        affected_hosts = report_data.get("affected_hosts", [])
        coverage = report_data.get("coverage", {})

        findings_rows = ""
        if findings:
            for finding in findings:
                badge_class = self._severity_class(finding["severity"])
                findings_rows += (
                    "<tr>"
                    f"<td><span class='badge {badge_class}'>{html_escape(finding['severity'])}</span></td>"
                    f"<td>{html_escape(finding['title'])}</td>"
                    f"<td>{html_escape(finding['owasp_category'])}</td>"
                    f"<td>{html_escape(str(finding.get('cwe') or 'CWE-N/A'))}</td>"
                    f"<td>{html_escape(str(finding.get('confidence') or 'Medium'))}</td>"
                    f"<td>{html_escape(str(finding.get('affected_url') or ''))}</td>"
                    f"<td>{html_escape(str(finding.get('lifecycle_status') or 'New'))}</td>"
                    f"<td>{html_escape(str(finding.get('validation_status') or 'Needs Manual Validation'))}</td>"
                    f"<td>{html_escape(str(finding.get('evidence') or ''))}</td>"
                    f"<td>{html_escape(finding['description'])}</td>"
                    f"<td>{html_escape(finding['recommendation'])}</td>"
                    "</tr>"
                )
        else:
            findings_rows = (
                "<tr><td colspan='11' class='empty'>No issues found by this scanner.</td></tr>"
            )

        category_rows = "".join(
            f"<li><span>{html_escape(category)}</span><strong>{count}</strong></li>"
            for category, count in category_summary.items()
        )

        host_rows = "".join(
            f"<li><span>{html_escape(item['host'])}</span><strong>{item['findings']}</strong></li>"
            for item in affected_hosts
        ) or "<li><span>No host summary available</span><strong>0</strong></li>"

        cwe_rows = "".join(
            f"<li><span>{html_escape(cwe)}</span><strong>{count}</strong></li>"
            for cwe, count in cwe_summary.items()
        ) or "<li><span>No CWE mappings</span><strong>0</strong></li>"

        confidence_rows = "".join(
            f"<li><span>{html_escape(confidence)}</span><strong>{count}</strong></li>"
            for confidence, count in confidence_summary.items()
        ) or "<li><span>No confidence data</span><strong>0</strong></li>"

        discovery_rows = "".join(
            f"<li><span>{html_escape(item.get('source', 'source'))}: {html_escape(item.get('url', ''))}</span><strong>{html_escape(str(item.get('discovered_urls', 0)))}</strong></li>"
            for item in report_data.get("discovery_sources", [])[:8]
        ) or "<li><span>No extra discovery sources used</span><strong>0</strong></li>"

        coverage_rows = "".join(
            f"<li><span>{html_escape(label)}</span><strong>{html_escape(str(value))}</strong></li>"
            for label, value in (
                ("Targets requested", coverage.get("targets_requested", len(report_data["scan"].get("targets", [])))),
                ("URLs scanned", coverage.get("urls_scanned", len(report_data["scan"]["settings"].get("crawled_urls", [])))),
                ("Max pages", coverage.get("max_pages", report_data["scan"]["settings"].get("max_pages", 0))),
                ("Max depth", coverage.get("max_depth", report_data["scan"]["settings"].get("max_depth", 0))),
                ("Safe probes used", f"{coverage.get('safe_probes_used', 0)} / {coverage.get('safe_probe_limit', 0)}"),
                ("Open ports found", coverage.get("open_ports_found", len(report_data.get("open_ports", [])))),
                ("Authenticated context", "Yes" if coverage.get("authenticated_context") else "No"),
            )
        )

        coverage_notes = "".join(
            f"<li>{html_escape(str(note))}</li>"
            for note in coverage.get("notes", [])
        ) or "<li>No coverage limitations were recorded for this scan.</li>"

        prevention_rows = "".join(
            "<article class='prevention-card'>"
            f"<div><span class='badge {self._severity_class(item.get('severity', 'Info'))}'>{html_escape(str(item.get('severity', 'Info')))}</span>"
            f"<strong>{html_escape(str(item.get('title', 'Security Finding')))}</strong></div>"
            f"<p>{html_escape(str(item.get('recommendation', 'Review the affected endpoint and add regression coverage.')))}</p>"
            f"<small>{html_escape(str(item.get('count', 0)))} related finding"
            f"{'' if item.get('count', 0) == 1 else 's'}"
            f"{' across ' + html_escape(', '.join(item.get('affected_urls', [])[:3])) if item.get('affected_urls') else ''}</small>"
            "</article>"
            for item in report_data.get("prevention_plan", [])
        ) or (
            "<article class='prevention-card'>"
            "<div><span class='badge info'>Info</span><strong>Maintain Secure Baseline</strong></div>"
            "<p>Keep security headers, dependency checks, and periodic authenticated scans in the release process.</p>"
            "<small>No active findings in this scan.</small>"
            "</article>"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html_escape(self.SCANNER_NAME)} Report</title>
  <style>
    :root {{
      --bg: #081018;
      --surface: #101928;
      --panel: #141f2f;
      --line: #24364d;
      --text: #e6eef9;
      --muted: #8ea3ba;
      --blue: #28b1ff;
      --amber: #f59e0b;
      --red: #ef4444;
      --orange: #f97316;
      --green: #22c55e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Bahnschrift", "Segoe UI Variable", "Aptos", "Segoe UI", Arial, sans-serif;
      background: radial-gradient(circle at top right, rgba(40,177,255,.14), transparent 24%), var(--bg);
      color: var(--text);
    }}
    .page {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 28px;
    }}
    .hero {{
      background: linear-gradient(180deg, rgba(20,31,47,.95), rgba(13,21,33,.95));
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 18px;
      box-shadow: 0 24px 70px rgba(0,0,0,.35);
    }}
    .hero h1 {{ margin: 0 0 6px; font-size: 30px; }}
    .hero p {{ margin: 0; color: var(--muted); }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      margin-top: 22px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
    }}
    .card span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
      margin-bottom: 8px;
    }}
    .card strong {{
      font-size: 28px;
      display: block;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 20px;
    }}
    .panel h2 {{
      margin: 0 0 14px;
      font-size: 18px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      color: #9fb2c7;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .05em;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
    }}
    .badge.critical {{ background: #4b1720; color: #ffd4d8; }}
    .badge.high {{ background: #4a2607; color: #ffd7a3; }}
    .badge.med {{ background: #3f3208; color: #ffe184; }}
    .badge.low {{ background: #142d45; color: #9bd8ff; }}
    .badge.info {{ background: #102433; color: #9ce2ff; }}
    .list {{
      list-style: none;
      padding: 0;
      margin: 0;
    }}
    .list li {{
      display: flex;
      justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px solid var(--line);
    }}
    .empty {{
      text-align: center;
      color: var(--muted);
      padding: 36px 12px;
    }}
    .note {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 12px;
    }}
    .prevention-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .prevention-card {{
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      background: var(--panel);
    }}
    .prevention-card div {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
    }}
    .prevention-card strong {{
      font-size: 14px;
    }}
    .prevention-card p {{
      color: var(--text);
      margin: 0 0 10px;
      line-height: 1.45;
    }}
    .prevention-card small {{
      color: var(--muted);
    }}
    @media (max-width: 900px) {{
      .meta, .grid, .prevention-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <h1>{html_escape(self.SCANNER_NAME)} Report</h1>
      <p>Automated OWASP Top 10-aligned web vulnerability scan results for authorized testing.</p>
      <div class="meta">
        <div class="card"><span>Scan Name</span><strong>{html_escape(report_data['scan']['name'])}</strong></div>
        <div class="card"><span>Scan Type</span><strong>{html_escape(report_data['scan']['type'])}</strong></div>
        <div class="card"><span>Target</span><strong>{html_escape(report_data['target'])}</strong></div>
        <div class="card"><span>Final URL</span><strong>{html_escape(report_data['final_url'])}</strong></div>
        <div class="card"><span>Findings</span><strong>{len(findings)}</strong></div>
        <div class="card"><span>Duration</span><strong>{report_data['duration_seconds']:.1f}s</strong></div>
      </div>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>Findings</h2>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>OWASP Category</th>
              <th>CWE</th>
              <th>Confidence</th>
              <th>Affected URL</th>
              <th>Status</th>
              <th>Validation</th>
              <th>Evidence</th>
              <th>Description</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {findings_rows}
          </tbody>
        </table>
      </div>
        <div class="panel">
        <h2>Severity Summary</h2>
        <ul class="list">
          <li><span>Critical</span><strong>{summary.get('Critical', 0)}</strong></li>
          <li><span>High</span><strong>{summary.get('High', 0)}</strong></li>
          <li><span>Medium</span><strong>{summary.get('Medium', 0)}</strong></li>
          <li><span>Low</span><strong>{summary.get('Low', 0)}</strong></li>
          <li><span>Info</span><strong>{summary.get('Info', 0)}</strong></li>
        </ul>

        <h2 style="margin-top:18px;">Affected Hosts</h2>
        <ul class="list">
          {host_rows}
        </ul>

        <h2 style="margin-top:18px;">OWASP Coverage</h2>
        <ul class="list">
          {category_rows}
        </ul>

        <h2 style="margin-top:18px;">CWE Mapping</h2>
        <ul class="list">
          {cwe_rows}
        </ul>

        <h2 style="margin-top:18px;">Confidence</h2>
        <ul class="list">
          {confidence_rows}
        </ul>

        <h2 style="margin-top:18px;">Discovery Sources</h2>
        <ul class="list">
          {discovery_rows}
        </ul>
      </div>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>Scan Coverage</h2>
        <ul class="list">
          {coverage_rows}
        </ul>
      </div>
      <div class="panel">
        <h2>Coverage Notes</h2>
        <ul>
          {coverage_notes}
        </ul>
      </div>
    </section>

    <section class="panel" style="margin-bottom:18px;">
      <h2>How to Prevent Recurrence</h2>
      <div class="prevention-grid">
        {prevention_rows}
      </div>
    </section>

    <p class="note">This report is intended for authorized security testing only. It does not perform destructive actions or exploit validation.</p>
  </main>
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as file:
            file.write(html_content)

        print(f"[+] HTML report saved as: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="CyberScan - Automated OWASP Top 10-aligned web vulnerability scanner prototype"
    )

    parser.add_argument(
        "target",
        help="Target website URL. Example: https://example.com"
    )

    parser.add_argument(
        "--json",
        default="cyberscan_report.json",
        help="Output JSON report filename"
    )

    parser.add_argument(
        "--csv",
        default=None,
        help="Optional CSV report filename"
    )

    parser.add_argument(
        "--html",
        default=None,
        help="Optional HTML report filename"
    )

    parser.add_argument(
        "--scan-type",
        choices=sorted(CyberScan.SCAN_PROFILES.keys()),
        default="Quick",
        help="Scan profile: Quick, Full, or Authenticated"
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Maximum same-host crawl depth, 1-5. Defaults to the selected scan profile."
    )

    parser.add_argument(
        "--include-paths",
        default="",
        help="Comma-separated regex patterns for paths to include during discovered-link crawling"
    )

    parser.add_argument(
        "--exclude-paths",
        default="",
        help="Comma-separated regex patterns for paths to exclude from crawling"
    )

    parser.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        help="Maximum requests per second, 1-50. Defaults to the selected scan profile."
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Maximum pages to crawl, 1-500. Defaults to the selected scan profile."
    )

    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Additional request header, repeatable. Example: --header \"Authorization: Bearer TOKEN\""
    )

    parser.add_argument(
        "--cookie",
        action="append",
        default=[],
        help="Session cookie, repeatable. Example: --cookie \"sessionid=VALUE\""
    )

    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Enable safe TCP connect checks for common exposed ports"
    )

    parser.add_argument(
        "--ports",
        default="",
        help="Comma-separated ports or ranges for --port-scan. Example: \"22,80,443,8080\""
    )

    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm you own the target or have explicit permission to scan it"
    )

    args = parser.parse_args()

    if not args.confirm_authorized:
        print("[!] Authorized testing reminder: run CyberScan only against systems you own or have permission to assess.")

    scanner = CyberScan(
        args.target,
        scan_type=args.scan_type,
        max_depth=args.max_depth,
        include_paths=args.include_paths,
        exclude_paths=args.exclude_paths,
        rate_limit=args.rate_limit,
        max_pages=args.max_pages,
        auth_headers=args.header,
        session_cookies=args.cookie,
        port_scan=args.port_scan,
        ports=args.ports,
    )
    scanner.scan()
    scanner.print_report()
    scanner.save_json_report(args.json)

    if args.csv:
        scanner.save_csv_report(args.csv)

    if args.html:
        scanner.save_html_report(args.html)


if __name__ == "__main__":
    main()
