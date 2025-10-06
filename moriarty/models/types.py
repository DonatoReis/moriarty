from __future__ import annotations

from enum import Enum


class EntityKind(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    DOMAIN = "domain"
    IP_ADDRESS = "ip"
    ORGANIZATION = "organization"


class EvidenceKind(str, Enum):
    NETWORK = "network"
    WEB = "web"
    FILE = "file"
    MANUAL = "manual"


class ConfidenceBand(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    INDICATIVE = "indicative"


__all__ = ["EntityKind", "EvidenceKind", "ConfidenceBand"]
