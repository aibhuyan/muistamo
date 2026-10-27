import pytest
from muistamo_contracts.v1.entraidentitybinding import EntraIdentityBinding


def binding() -> dict:
    return {
        "tenantId": "11111111-1111-4111-8111-111111111111",
        "bindingVersion": "22222222-2222-4222-8222-222222222222",
        "entraTenantId": "33333333-3333-4333-8333-333333333333",
        "blueprintAppId": "44444444-4444-4444-8444-444444444444",
        "blueprintObjectId": "55555555-5555-4555-8555-555555555555",
        "blueprintPrincipalId": "66666666-6666-4666-8666-666666666666",
        "sponsorUserIds": ["77777777-7777-4777-8777-777777777777"],
        "credentialRef": "entra-development",
        "credentialVersion": "version-1",
    }


def test_generated_binding_preserves_operator_configuration() -> None:
    document = binding()
    assert EntraIdentityBinding.model_validate(document).model_dump() == document


@pytest.mark.parametrize("field", ["clientSecret", "graphUrl", "authority", "credentialPath"])
def test_binding_excludes_inline_secret_and_endpoint_overrides(field: str) -> None:
    document = binding()
    document[field] = "obviously-fake-test-secret"
    with pytest.raises(ValueError):
        EntraIdentityBinding.model_validate(document)


@pytest.mark.parametrize("field", ["bindingVersion", "credentialVersion", "sponsorUserIds"])
def test_binding_requires_pinned_versions_and_sponsors(field: str) -> None:
    document = binding()
    del document[field]
    with pytest.raises(ValueError):
        EntraIdentityBinding.model_validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("entraTenantId", "common"),
        ("blueprintAppId", "../attacker?secret=value"),
        ("sponsorUserIds", []),
        ("credentialRef", "https://attacker.invalid/secret"),
    ],
)
def test_binding_rejects_malformed_scope_and_credentials(field: str, value: object) -> None:
    document = binding()
    document[field] = value
    with pytest.raises(ValueError):
        EntraIdentityBinding.model_validate(document)
