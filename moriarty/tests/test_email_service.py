from __future__ import annotations

import asyncio

from moriarty.modules.email_check import EmailCheckOptions, EmailCheckService


def test_email_normalization_only() -> None:
    service = EmailCheckService(
        email="Alice@Example.COM",
        options=EmailCheckOptions(check_dns=False, check_smtp=False),
        timeout=0.1,
    )
    result = asyncio.run(service.run())
    assert result.normalized_email == "alice@example.com"
    assert result.dns is None
    assert result.smtp is None
