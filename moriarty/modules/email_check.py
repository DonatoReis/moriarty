from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from email_validator import EmailNotValidError, validate_email

from ..net.dns_client import DNSClient, DNSLookupResult
from ..net.smtp_client import SMTPClient, SMTPProbeResult


@dataclass(slots=True)
class EmailCheckOptions:
    check_dns: bool = True
    check_smtp: bool = False
    from_address: str = "postmaster@localhost"
    retries: int = 1
    wait: float = 1.0


@dataclass(slots=True)
class EmailCheckResult:
    input_email: str
    normalized_email: str
    local_part: str
    domain: str
    dns: Optional[DNSLookupResult]
    smtp: Optional[SMTPProbeResult]
    warnings: List[str]


class EmailCheckService:
    """Run DNS and SMTP probes for an email address."""

    def __init__(self, email: str, options: EmailCheckOptions, timeout: float = 8.0) -> None:
        self._raw_email = email
        self._options = options
        self._timeout = timeout

    async def run(self) -> EmailCheckResult:
        normalized = self._normalize_email(self._raw_email)
        domain = normalized["domain"]
        local_part = normalized["local_part"]
        warnings: List[str] = []

        dns_result: Optional[DNSLookupResult] = None
        if self._options.check_dns:
            dns_client = DNSClient(timeout=self._timeout)
            dns_result = await dns_client.lookup_domain(domain)
            if not dns_result.mx:
                warnings.append("Domain has no MX records; falling back to A/AAAA for SMTP.")

        smtp_result: Optional[SMTPProbeResult] = None
        if self._options.check_smtp:
            smtp_client = SMTPClient(timeout=self._timeout, wait=self._options.wait, retries=self._options.retries)
            hosts: List[str] = []
            if dns_result and dns_result.mx:
                hosts = [record.exchange.rstrip('.') for record in dns_result.mx]
            elif dns_result and (dns_result.a or dns_result.aaaa):
                hosts = [domain]
            else:
                hosts = [domain]
                warnings.append("No DNS information available; SMTP probe will target the domain directly.")

            smtp_result = await smtp_client.probe(
                email=normalized["email"],
                from_address=self._options.from_address,
                hosts=hosts,
            )

        return EmailCheckResult(
            input_email=self._raw_email,
            normalized_email=normalized["email"],
            local_part=local_part,
            domain=domain,
            dns=dns_result,
            smtp=smtp_result,
            warnings=warnings,
        )

    @staticmethod
    def _normalize_email(raw_email: str) -> dict[str, str]:
        try:
            validated = validate_email(raw_email, check_deliverability=False)
        except EmailNotValidError as exc:
            raise ValueError(f"Invalid email address: {exc}") from exc

        normalized_attr = getattr(validated, "normalized", None)
        normalized_email = (normalized_attr or validated.email).lower()
        local_part, domain = normalized_email.split("@", 1)
        return {
            "email": normalized_email,
            "local_part": local_part,
            "domain": domain,
        }


__all__ = ["EmailCheckOptions", "EmailCheckResult", "EmailCheckService"]
