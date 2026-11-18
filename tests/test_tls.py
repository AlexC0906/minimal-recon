from datetime import datetime, timedelta, timezone
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from minimal_recon.services.tls import _flatten_name, inspect_tls


def _self_signed_certificate(tmp_path, not_after):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Minimal Recon Tests"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - timedelta(days=30))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def tls_server(tmp_path):
    """Serve a self-signed certificate on a local port for a few handshakes."""

    def start(not_after):
        cert_path, key_path = _self_signed_certificate(tmp_path, not_after)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        listener = socket.create_server(("127.0.0.1", 0))
        listener.settimeout(5)
        listeners.append(listener)

        def serve():
            while True:
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                try:
                    with context.wrap_socket(connection, server_side=True) as tls_connection:
                        tls_connection.recv(1)
                except OSError:
                    pass  # the client aborts the first, verified handshake

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    listeners = []
    yield start
    for listener in listeners:
        listener.close()


def test_inspect_tls_reports_certificate_that_fails_validation(tls_server):
    port = tls_server(datetime.now(timezone.utc) + timedelta(days=10, hours=1))

    result = inspect_tls("127.0.0.1", port, timeout=5)

    assert result.verified is False
    assert result.verification_error
    assert result.subject == "commonName=selfsigned.test, organizationName=Minimal Recon Tests"
    assert result.issuer == result.subject
    assert result.days_until_expiry == 10
    assert result.tls_version.startswith("TLS")
    assert datetime.fromisoformat(result.not_after).utcoffset().total_seconds() == 0


def test_inspect_tls_reports_negative_days_for_expired_certificate(tls_server):
    port = tls_server(datetime.now(timezone.utc) - timedelta(days=2, hours=1))

    result = inspect_tls("127.0.0.1", port, timeout=5)

    assert result.verified is False
    assert result.days_until_expiry < 0


def test_flatten_name_reads_certificate_fields():
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])

    assert _flatten_name(name) == "commonName=example.test"


@pytest.mark.parametrize("hostname, port", [("https://example.test", 443), ("example.test", 0)])
def test_inspect_tls_validates_input_before_connecting(hostname, port):
    with pytest.raises(ValueError):
        inspect_tls(hostname, port)
