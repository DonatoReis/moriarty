from __future__ import annotations

from typing import Any, Dict, Optional, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .types import EntityKind


class Entity(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    kind: EntityKind
    value: str
    display_name: Optional[str] = None
    labels: Set[str] = Field(default_factory=set)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True, populate_by_name=True)


__all__ = ["Entity"]
