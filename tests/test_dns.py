import pytest

from minimal_recon.services.dns import enumerate_dns, normalize_domain


class FakeAnswer:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeResolver:
    def resolve(self, domain, record_type, lifetime):
        records = {
            "A": [FakeAnswer("192.0.2.10")],
            "MX": [FakeAnswer("10 mail.example.test.")],
        }
        if record_type not in records:
            raise OSError("record unavailable")
        return records[record_type]


def test_normalize_domain_strips_whitespace_and_root_dot():
    assert normalize_domain("  example.test. ") == "example.test"


def test_enumerate_dns_uses_injected_resolver():
    result = enumerate_dns("example.test.", resolver=FakeResolver())

    assert result == {
        "A": ["192.0.2.10"],
        "MX": ["10 mail.example.test."],
    }


@pytest.mark.parametrize("domain", ["", "example test", "example..test"])
def test_normalize_domain_rejects_invalid_names(domain):
    with pytest.raises(ValueError):
        normalize_domain(domain)
