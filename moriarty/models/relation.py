from __future__ import annotations

from typing import Dict, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .types import ConfidenceBand


class Relation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    target_id: UUID
    relation_type: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    band: ConfidenceBand = ConfidenceBand.INDICATIVE
    attributes: Dict[str, str] = Field(default_factory=dict)
    description: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


__all__ = ["Relation"]
