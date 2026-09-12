from minimal_recon.services.antispoofing import analyze_anti_spoofing


class FakeAnswer:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeResolver:
    def resolve(self, name, record_type, lifetime):
        records = {
            "example.test": ['"v=spf1 include:_spf.example.test -all"'],
            "_dmarc.example.test": ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.test"'],
            "google._domainkey.example.test": ['"v=DKIM1; k=rsa; p=public-key"'],
        }
        if name not in records:
            raise OSError("record unavailable")
        return [FakeAnswer(value) for value in records[name]]


def test_analyze_anti_spoofing_reads_spf_dmarc_and_dkim():
    result = analyze_anti_spoofing("Example.Test", ["google", "missing"], FakeResolver())

    assert result.spf_status == "pass"
    assert result.dmarc_status == "strong"
    assert result.dmarc_policy == "reject"
    assert result.dkim_status == "partial"
    assert "google" in result.dkim_selectors


def test_dmarc_parser_handles_compact_tags():
    result = analyze_anti_spoofing("example.test", resolver=FakeResolver())

    assert result.dmarc_policy == "reject"


def test_analyze_anti_spoofing_marks_missing_controls():
    result = analyze_anti_spoofing("empty.test", resolver=FakeResolver())

    assert result.spf_status == "missing"
    assert result.dmarc_status == "missing"
    assert result.dkim_status == "not_checked"
    assert len(result.findings) == 2
