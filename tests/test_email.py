import pytest

from minimal_recon.services.email import analyze_email


class FakeAnswer:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeResolver:
    def resolve(self, domain, record_type, lifetime):
        assert domain == "example.test"
        assert record_type == "MX"
        return [FakeAnswer("10 mail.example.test.")]


class FlexibleResolver:
    def resolve(self, domain, record_type, lifetime):
        return [FakeAnswer("10 mail.example.test.")]


def test_analyze_email_normalizes_domain_and_reads_mx():
    result = analyze_email(" analyst@Example.Test ", resolver=FakeResolver())

    assert result.email == "analyst@Example.Test"
    assert result.local_part == "analyst"
    assert result.domain == "example.test"
    assert result.mx_records == ["10 mail.example.test."]
    assert result.mx_available is True
    assert result.is_role_address is False
    assert result.risk_flags == []


def test_analyze_email_flags_role_and_disposable_domain():
    result = analyze_email(" support@mailinator.com ", resolver=FlexibleResolver())

    assert result.is_role_address is True
    assert result.is_disposable_domain is True
    assert result.risk_flags == ["role_address", "disposable_domain"]


@pytest.mark.parametrize("address", ["", "missing-at", "a@@example.test", "a" * 65 + "@example.test"])
def test_analyze_email_rejects_invalid_addresses(address):
    with pytest.raises(ValueError):
        analyze_email(address)
