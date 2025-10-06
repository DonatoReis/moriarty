from __future__ import annotations

from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .types import ConfidenceBand


class Assertion(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    subject_id: UUID
    predicate: str
    object: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    band: ConfidenceBand = ConfidenceBand.INDICATIVE
    evidence_ids: List[UUID] = Field(default_factory=list)
    explanation: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


__all__ = ["Assertion"]
