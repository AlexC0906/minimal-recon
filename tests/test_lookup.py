from minimal_recon.services.lookup import lookup_target


def test_lookup_identifies_ipv4(monkeypatch):
    monkeypatch.setattr("socket.gethostbyaddr", lambda target: ("example.test", [], [target]))

    result = lookup_target("192.0.2.10")

    assert result.target_type == "IPv4"
    assert result.addresses == ("192.0.2.10",)
    assert result.reverse_name == "example.test"


def test_lookup_allows_missing_reverse_dns(monkeypatch):
    def missing_reverse_dns(target):
        raise OSError("reverse lookup unavailable")

    monkeypatch.setattr("socket.gethostbyaddr", missing_reverse_dns)

    result = lookup_target("192.0.2.10")

    assert result.reverse_name is None


def test_lookup_reports_unresolvable_domain_clearly(monkeypatch):
    import socket

    import pytest

    def failing_getaddrinfo(*args):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr("socket.getaddrinfo", failing_getaddrinfo)

    with pytest.raises(OSError, match="could not resolve missing.example.test"):
        lookup_target("missing.example.test")


def test_lookup_rejects_urls():
    import pytest

    with pytest.raises(ValueError):
        lookup_target("https://example.test")
