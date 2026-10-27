import pytest
from muistamo_contracts.v1.identityoperationstatus import IdentityOperationStatus
from pydantic import ValidationError


def operation():
    return {
        "tenantId": "11111111-1111-4111-8111-111111111111",
        "id": "22222222-2222-4222-8222-222222222222",
        "instanceIdentityId": "33333333-3333-4333-8333-333333333333",
        "bindingVersion": "44444444-4444-4444-8444-444444444444",
        "hrReceiptId": "55555555-5555-4555-8555-555555555555",
        "hrGeneration": 1,
        "action": "create",
        "attempt": 1,
        "state": "pending",
        "creationId": "22222222-2222-4222-8222-222222222222",
        "createdAt": "2026-10-27T09:00:00Z",
        "updatedAt": "2026-10-27T09:00:00Z",
    }


def test_journal_uses_opaque_correlation():
    assert IdentityOperationStatus.model_validate(operation()).hrGeneration == 1


@pytest.mark.parametrize(
    "field", ["email", "personId", "hrEventId", "credential", "token", "response"]
)
def test_journal_refuses_personal_payloads_and_credentials(field):
    value = operation()
    value[field] = "obviously-fake-unwanted-value"
    with pytest.raises(ValidationError):
        IdentityOperationStatus.model_validate(value)


@pytest.mark.parametrize(
    "field,value", [("hrGeneration", 0), ("state", "retry_create"), ("hrReceiptId", "raw-hr-key")]
)
def test_journal_refuses_unfenced_status(field, value):
    document = operation()
    document[field] = value
    with pytest.raises(ValidationError):
        IdentityOperationStatus.model_validate(document)
