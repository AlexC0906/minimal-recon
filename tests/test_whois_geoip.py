import httpx
import pytest

from minimal_recon.services.geoip import geolocate_ip
from minimal_recon.services.whois import lookup_whois


class FakeWhoisClient:
    def get(self, url):
        return httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                ],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}],
            },
            request=httpx.Request("GET", url),
        )


class FakeGeoClient:
    def get(self, url):
        return httpx.Response(
            200,
            json={
                "success": True,
                "country": "Exampleland",
                "country_code": "EX",
                "region": "Example Region",
                "city": "Example City",
                "latitude": 1.2,
                "longitude": 3.4,
                "connection": {"isp": "Example ISP", "org": "Example Hosting", "asn": "AS64500"},
            },
            request=httpx.Request("GET", url),
        )


def test_lookup_whois_reads_registration_and_registrar():
    result = lookup_whois("Example.Test.", client=FakeWhoisClient())

    assert result.domain == "example.test"
    assert result.registrar == "Example Registrar"
    assert result.registration_date == "2020-01-01T00:00:00Z"
    assert result.nameservers == ["ns1.example.test"]


def test_geolocate_ip_reads_location_and_network():
    result = geolocate_ip("192.0.2.10", client=FakeGeoClient())

    assert result.country == "Exampleland"
    assert result.city == "Example City"
    assert result.organization == "Example Hosting"
    assert result.asn == "AS64500"


@pytest.mark.parametrize("ip", ["not-an-ip", "example.test"])
def test_geolocate_ip_rejects_non_ip_values(ip):
    with pytest.raises(ValueError):
        geolocate_ip(ip, client=FakeGeoClient())
