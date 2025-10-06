from __future__ import annotations

from datetime import datetime

from moriarty.net.tls_client import TLSClient


def test_tls_parse_time() -> None:
    client = TLSClient()
    parsed = client._parse_time("Jan 01 00:00:00 2024 GMT")
    assert isinstance(parsed, datetime)
    assert parsed.year == 2024


def test_tls_parse_time_default() -> None:
    client = TLSClient()
    parsed = client._parse_time(None)
    assert parsed == datetime.fromtimestamp(0)
