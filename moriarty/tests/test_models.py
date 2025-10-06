from __future__ import annotations

from moriarty.models import (
    Assertion,
    ConfidenceBand,
    CustodyEvent,
    Entity,
    EntityKind,
    Evidence,
    EvidenceKind,
    Relation,
)


def test_entity_creation() -> None:
    entity = Entity(kind=EntityKind.EMAIL, value="alice@example.com")
    assert entity.value == "alice@example.com"
    assert entity.kind is EntityKind.EMAIL


def test_evidence_chain() -> None:
    evidence = Evidence(
        kind=EvidenceKind.NETWORK,
        sha256="deadbeef",
        source="dns",
        custody=[CustodyEvent(actor="tester", action="collected")],
    )
    assert evidence.custody[0].actor == "tester"


def test_assertion_defaults() -> None:
    entity = Entity(kind=EntityKind.DOMAIN, value="example.com")
    assertion = Assertion(
        subject_id=entity.id,
        predicate="resolves_to",
        object="93.184.216.34",
    )
    assert assertion.band == ConfidenceBand.INDICATIVE


def test_relation_attributes() -> None:
    src = Entity(kind=EntityKind.EMAIL, value="alice@example.com")
    dst = Entity(kind=EntityKind.USERNAME, value="alice")
    relation = Relation(source_id=src.id, target_id=dst.id, relation_type="aka")
    assert relation.source_id == src.id
    assert relation.relation_type == "aka"
