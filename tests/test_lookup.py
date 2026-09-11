from minimal_recon.services.lookup import lookup_target


def test_lookup_identifies_ipv4(monkeypatch):
    monkeypatch.setattr("socket.gethostbyaddr", lambda target: ("example.test", [], [target]))

    result = lookup_target("192.0.2.10")

    assert result.target_type == "IPv4"
    assert result.addresses == ("192.0.2.10",)
    assert result.reverse_name == "example.test"
