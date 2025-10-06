"""HTTP fingerprinting and lightweight technology detection (Wappalyzer-style)."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urljoin

import httpx
import structlog

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from moriarty.modules.stealth_mode import StealthMode


logger = structlog.get_logger(__name__)


@dataclass
class TechnologyDetection:
    """Single technology detection with evidence metadata."""

    name: str
    confidence: int
    evidence: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


DEFAULT_ENDPOINTS = [
    "/",
    "/robots.txt",
    "/manifest.json",
    "/.well-known/security.txt",
    "/wp-json/",
    "/graphql",
]


async def profile_domain(
    domain: str,
    session: Optional[httpx.AsyncClient] = None,
    *,
    base_url: Optional[str] = None,
    stealth: Optional["StealthMode"] = None,
    timeout: float = 10.0,
    endpoints: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Collect headers, interesting endpoints and infer running technologies.

    Parameters
    ----------
    domain: str
        Domain to fingerprint (without scheme).
    session: Optional[httpx.AsyncClient]
        Optional client to reuse. If omitted a temporary client is created.
    base_url: Optional[str]
        Override base URL (defaults to https://<domain>).
    stealth: Optional[StealthMode]
        When provided, randomizes headers/timing similarly to the StealthMode module.
    timeout: float
        Per-request timeout when creating a temporary client.
    endpoints: Optional[List[str]]
        Overrides the default endpoint list.
    """

    created_client = False
    if session is None:
        session = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        created_client = True

    profile: Dict[str, Any] = {"headers": {}, "endpoints": {}, "detections": []}
    detections: List[TechnologyDetection] = []
    targets = endpoints or DEFAULT_ENDPOINTS
    root_url = base_url or f"https://{domain}"

    try:
        base_headers = _build_headers(stealth)
        logger.debug("techprofiler.fetch.base", url=root_url)
        try:
            response = await session.get(root_url, headers=base_headers)
        except Exception as exc:
            logger.debug("techprofiler.base.error", url=root_url, error=str(exc))
            response = None

        if response is not None:
            profile["headers"] = dict(response.headers)
            detections.extend(_detect_from_headers(response.headers))
            if response.headers.get("set-cookie"):
                detections.extend(_detect_from_cookies(response.headers.get("set-cookie", "")))

        async def fetch(path: str) -> None:
            url = urljoin(root_url, path)
            headers = _build_headers(stealth)
            try:
                resp = await session.get(url, headers=headers)
            except Exception as exc:  # pragma: no cover - network errors tolerated
                logger.debug("techprofiler.endpoint.error", url=url, error=str(exc))
                return

            if resp.status_code >= 400:
                logger.debug("techprofiler.endpoint.skip", url=url, status=resp.status_code)
                return

            record: Dict[str, Any] = {"status": resp.status_code}
            content_type = resp.headers.get("content-type", "").lower()
            body_sample: Optional[str] = None

            if "json" in content_type:
                try:
                    record["json"] = resp.json()
                except Exception:
                    body_sample = resp.text[:400]
            else:
                body_sample = resp.text[:400]

            if body_sample:
                record["snippet"] = body_sample
            profile["endpoints"][path] = record

            detections.extend(_detect_from_endpoint(path, resp, body_sample))

        await asyncio.gather(*(fetch(ep) for ep in targets))

        # Aggregate detections (dedupe by name keeping highest confidence)
        aggregated: Dict[str, TechnologyDetection] = {}
        for detection in detections:
            existing = aggregated.get(detection.name)
            if not existing or detection.confidence > existing.confidence:
                aggregated[detection.name] = detection
            elif existing and detection.evidence:
                # merge new evidence/tags/categories when confidence tie
                for bucket, value in (
                    ("evidence", detection.evidence),
                    ("categories", detection.categories),
                    ("tags", detection.tags),
                ):
                    merged = getattr(existing, bucket)
                    for item in value:
                        if item not in merged:
                            merged.append(item)

        profile["detections"] = [det.to_dict() for det in aggregated.values()]
        profile["components"] = _build_component_index(profile["detections"])
        return profile

    finally:
        if created_client:
            await session.aclose()


def _build_headers(stealth: Optional["StealthMode"]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if stealth:
        headers.update(stealth.get_random_headers())
    headers.setdefault("User-Agent", "Mozilla/5.0 (Moriarty Recon)")
    headers.setdefault("Accept", "*/*")
    return headers


def _detect_from_headers(headers: httpx.Headers) -> List[TechnologyDetection]:
    detections: List[TechnologyDetection] = []
    server = headers.get("server")
    if server:
        name = server.split(" ")[0].split("/")[0]
        detections.append(
            TechnologyDetection(
                name=name,
                confidence=65,
                evidence=[f"Server header: {server}"],
                categories=["server"],
                tags=[name.lower()],
            )
        )

    powered = headers.get("x-powered-by")
    if powered:
        detections.append(
            TechnologyDetection(
                name=powered,
                confidence=80,
                evidence=[f"X-Powered-By: {powered}"],
                categories=["platform"],
                tags=[powered.split("/")[0].lower()],
            )
        )

    asp = headers.get("x-aspnet-version")
    if asp:
        detections.append(
            TechnologyDetection(
                name="ASP.NET",
                confidence=90,
                evidence=[f"X-AspNet-Version: {asp}"],
                categories=["framework"],
                tags=["aspnet", "dotnet", "microsoft"],
            )
        )

    if headers.get("cf-ray") or headers.get("cf-cache-status"):
        detections.append(
            TechnologyDetection(
                name="Cloudflare",
                confidence=90,
                evidence=["Cloudflare headers present"],
                categories=["cdn", "waf"],
                tags=["cloudflare"],
            )
        )

    if headers.get("akamai-ghost"):
        detections.append(
            TechnologyDetection(
                name="Akamai",
                confidence=80,
                evidence=["Akamai edge headers"],
                categories=["cdn"],
                tags=["akamai"],
            )
        )

    return detections


def _detect_from_cookies(cookie_header: str) -> List[TechnologyDetection]:
    detections: List[TechnologyDetection] = []
    cookie_header = cookie_header.lower()
    if "wordpress_logged_in" in cookie_header or "wp-settings" in cookie_header:
        detections.append(
            TechnologyDetection(
                name="WordPress",
                confidence=95,
                evidence=["WordPress session cookies"],
                categories=["cms"],
                tags=["wordpress", "php", "cms"],
            )
        )
    if "laravel_session" in cookie_header:
        detections.append(
            TechnologyDetection(
                name="Laravel",
                confidence=85,
                evidence=["Laravel session cookie"],
                categories=["framework"],
                tags=["laravel", "php"],
            )
        )
    if "mage-cache-sessid" in cookie_header or "mage-cache-storage" in cookie_header:
        detections.append(
            TechnologyDetection(
                name="Magento",
                confidence=80,
                evidence=["Magento session cookies"],
                categories=["ecommerce"],
                tags=["magento", "php", "ecommerce"],
            )
        )
    return detections


def _detect_from_endpoint(path: str, response: httpx.Response, snippet: Optional[str]) -> List[TechnologyDetection]:
    detections: List[TechnologyDetection] = []
    lowered_path = path.lower()
    snippet = snippet or ""

    if lowered_path.startswith("/wp-json"):
        detections.append(
            TechnologyDetection(
                name="WordPress",
                confidence=90,
                evidence=["/wp-json endpoint accessible"],
                categories=["cms"],
                tags=["wordpress", "php", "cms"],
            )
        )

    if lowered_path == "/robots.txt" and "wp-admin" in snippet:
        detections.append(
            TechnologyDetection(
                name="WordPress",
                confidence=70,
                evidence=["robots.txt contains wp-admin"],
                categories=["cms"],
                tags=["wordpress", "cms"],
            )
        )

    if lowered_path == "/graphql" and response.status_code == 200:
        detections.append(
            TechnologyDetection(
                name="GraphQL API",
                confidence=90,
                evidence=["/graphql responded with 200"],
                categories=["api"],
                tags=["graphql"],
            )
        )

    if lowered_path == "/manifest.json" and "gcm_sender_id" in snippet:
        detections.append(
            TechnologyDetection(
                name="Progressive Web App",
                confidence=60,
                evidence=["manifest.json contains PWA keys"],
                categories=["frontend"],
                tags=["pwa"],
            )
        )

    if snippet and 'SetEnvIfNoCase Request_URI "/wp-' in snippet:
        detections.append(
            TechnologyDetection(
                name="ModSecurity",
                confidence=55,
                evidence=["security.txt hints ModSecurity"],
                categories=["waf"],
                tags=["modsecurity"],
            )
        )

    if snippet and re.search(r"Drupal\s*\d", snippet, re.IGNORECASE):
        detections.append(
            TechnologyDetection(
                name="Drupal",
                confidence=60,
                evidence=["Endpoint content references Drupal"],
                categories=["cms"],
                tags=["drupal", "php", "cms"],
            )
        )

    if snippet and "woocommerce" in snippet.lower():
        detections.append(
            TechnologyDetection(
                name="WooCommerce",
                confidence=55,
                evidence=["Content references WooCommerce"],
                categories=["ecommerce"],
                tags=["woocommerce", "wordpress", "ecommerce"],
            )
        )

    return detections


def _build_component_index(detections: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    components: Dict[str, List[str]] = {}
    for detection in detections:
        for category in detection.get("categories", []):
            components.setdefault(category, [])
            name = detection.get("name")
            if name and name not in components[category]:
                components[category].append(name)
    return components


__all__ = ["profile_domain", "TechnologyDetection"]
