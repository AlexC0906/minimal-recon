import pytest

from minimal_recon.services.tls import _flatten_name, _parse_certificate_date


def test_flatten_name_reads_certificate_fields():
    assert _flatten_name(((('commonName', 'example.test'),),)) == "commonName=example.test"


def test_parse_certificate_date_is_utc():
    result = _parse_certificate_date("Jan 01 00:00:00 2030 GMT")

    assert result is not None
    assert result.year == 2030
    assert result.utcoffset().total_seconds() == 0


@pytest.mark.parametrize("value", [None, ""])
def test_parse_certificate_date_handles_missing_value(value):
    assert _parse_certificate_date(value) is None
