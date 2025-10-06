from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from time import perf_counter
from typing import Iterable, List, Optional

import aiosmtplib
import structlog


@dataclass(slots=True)
class SMTPAttempt:
    host: str
    port: int
    result_code: Optional[int]
    result_message: Optional[str]
    success: bool
    error: Optional[str]


@dataclass(slots=True)
class SMTPProbeResult:
    deliverable: bool
    attempts: List[SMTPAttempt]


class SMTPClient:
    def __init__(self, timeout: float = 8.0, wait: float = 1.0, retries: int = 1) -> None:
        self._timeout = timeout
        self._wait = wait
        self._retries = retries
        self._logger = structlog.get_logger(__name__)

    async def probe(self, email: str, from_address: str, hosts: Iterable[str]) -> SMTPProbeResult:
        attempts: List[SMTPAttempt] = []
        deliverable = False

        for host in hosts:
            start = perf_counter()
            self._logger.info(
                "smtp.probe.start",
                host=host,
                retries=self._retries,
                timeout_s=self._timeout,
            )
            for attempt in range(self._retries + 1):
                smtp: Optional[aiosmtplib.SMTP] = None
                try:
                    smtp = aiosmtplib.SMTP(hostname=host, port=25, timeout=self._timeout)
                    await smtp.connect()
                    await smtp.ehlo()
                    await smtp.mail(from_address)
                    rcpt_code, rcpt_message = await smtp.rcpt(email)
                    message_text = rcpt_message.decode("utf-8", errors="replace") if isinstance(rcpt_message, bytes) else str(rcpt_message)
                    success = 200 <= rcpt_code < 300
                    attempts.append(
                        SMTPAttempt(
                            host=host,
                            port=25,
                            result_code=rcpt_code,
                            result_message=message_text,
                            success=success,
                            error=None,
                        )
                    )
                    if success:
                        deliverable = True
                        await smtp.quit()
                        return SMTPProbeResult(deliverable=deliverable, attempts=attempts)
                except aiosmtplib.errors.SMTPException as exc:
                    attempts.append(
                        SMTPAttempt(
                            host=host,
                            port=25,
                            result_code=None,
                            result_message=None,
                            success=False,
                            error=str(exc),
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    attempts.append(
                        SMTPAttempt(
                            host=host,
                            port=25,
                            result_code=None,
                            result_message=None,
                            success=False,
                            error=str(exc),
                        )
                    )
                finally:
                    if smtp is not None:
                        with contextlib.suppress(Exception):
                            await smtp.quit()

                    if attempt < self._retries:
                        await asyncio.sleep(self._wait)

            latency_ms = (perf_counter() - start) * 1000
            self._logger.info(
                "smtp.probe.complete",
                host=host,
                attempts=len(attempts),
                latency_ms=round(latency_ms, 2),
                deliverable=deliverable,
            )

        return SMTPProbeResult(deliverable=deliverable, attempts=attempts)


__all__ = ["SMTPClient", "SMTPProbeResult", "SMTPAttempt"]
