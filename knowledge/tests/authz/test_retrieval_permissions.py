"""Invariant 1: retrieval never returns a document the acting person cannot open.

Placeholder until permission-preserving retrieval exists. It fails until then, by design.
"""

import importlib

import pytest

PERSON_A = "person-a@example.invalid"

# Document id -> people allowed to open it at the source.
DOCUMENTS = {
    "doc-allowed": {PERSON_A},
    "doc-secret": set(),
    "doc-other": {"person-b@example.invalid"},
}


def _retrieve():
    try:
        module = importlib.import_module("muistamo_knowledge.retrieval")
    except ModuleNotFoundError:
        pytest.fail(
            "no use-time-authorised retrieval path exists yet "
            "(expected muistamo_knowledge.retrieval.retrieve)"
        )
    return module.retrieve


@pytest.mark.authz
def test_retrieval_never_returns_a_document_the_person_cannot_open() -> None:
    retrieve = _retrieve()

    returned = {doc.id for doc in retrieve(acting_person=PERSON_A, query="quarterly report")}

    forbidden = {doc_id for doc_id, readers in DOCUMENTS.items() if PERSON_A not in readers}
    assert returned.isdisjoint(forbidden), f"leaked to {PERSON_A}: {returned & forbidden}"
    # Guards against an implementation that passes by returning nothing.
    assert "doc-allowed" in returned
