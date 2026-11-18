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


def _resolver_with(records):
    class Resolver:
        def resolve(self, name, record_type, lifetime):
            if name not in records:
                raise OSError("record unavailable")
            return [FakeAnswer(value) for value in records[name]]

    return Resolver()


def test_spf_permissive_all_is_weak():
    result = analyze_anti_spoofing("example.test", resolver=_resolver_with({"example.test": ['"v=spf1 +all"']}))

    assert result.spf_status == "weak"
    assert "SPF authorizes every sender (+all)" in result.findings


def test_multiple_spf_records_are_invalid():
    resolver = _resolver_with({"example.test": ['"v=spf1 -all"', '"v=spf1 include:other.test -all"']})

    result = analyze_anti_spoofing("example.test", resolver=resolver)

    assert result.spf_status == "invalid"


def test_spf_redirect_without_all_is_accepted():
    resolver = _resolver_with({"example.test": ['"v=spf1 redirect=_spf.example.test"']})

    assert analyze_anti_spoofing("example.test", resolver=resolver).spf_status == "pass"


def test_split_txt_record_is_joined_before_parsing():
    resolver = _resolver_with({"example.test": ['"v=spf1 include:_spf.example.test " "-all"']})

    result = analyze_anti_spoofing("example.test", resolver=resolver)

    assert result.spf_record == "v=spf1 include:_spf.example.test -all"
    assert result.spf_status == "pass"


def test_dmarc_partial_enforcement_and_missing_reports_are_flagged():
    resolver = _resolver_with(
        {
            "example.test": ['"v=spf1 -all"'],
            "_dmarc.example.test": ['"v=DMARC1; p = Quarantine; pct=25"'],
        }
    )

    result = analyze_anti_spoofing("example.test", resolver=resolver)

    assert result.dmarc_policy == "quarantine"
    assert result.dmarc_status == "strong"
    assert "DMARC policy applies to only 25% of mail (pct=25)" in result.findings
    assert "DMARC has no aggregate report address (rua)" in result.findings


def test_dmarc_without_policy_is_invalid():
    resolver = _resolver_with({"_dmarc.example.test": ['"v=DMARC1; rua=mailto:d@example.test"']})

    assert analyze_anti_spoofing("example.test", resolver=resolver).dmarc_status == "invalid"
