from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .types import EvidenceKind


class CustodyEvent(BaseModel):
    actor: str
    action: str
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None

    model_config = ConfigDict(frozen=True)


class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    kind: EvidenceKind
    sha256: str
    source: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    url: Optional[str] = None
    selector: Optional[str] = None
    method: Optional[str] = None
    summary: Optional[str] = None
    custody: List[CustodyEvent] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


__all__ = ["Evidence", "CustodyEvent"]
