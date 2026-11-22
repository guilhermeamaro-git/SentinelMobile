"""Geracao/reuso do certificado TLS autoassinado com SAN para IPs locais."""
import datetime
import ipaddress
import socket
from pathlib import Path
from typing import Iterable, List, Set, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_DIR = Path(__file__).parent / "certs"
CRT = CERT_DIR / "server.crt"
KEY = CERT_DIR / "server.key"
VALID_DAYS = 365


def detect_local_ips() -> List[str]:
    """IPs IPv4 da maquina. O primeiro e o da rota principal (ex.: hotspot)."""
    ips: List[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # UDP: nao envia pacote, so escolhe a rota
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(info[4][0])
    except OSError:
        pass
    out: List[str] = []
    for ip in ips:
        if ip != "0.0.0.0" and ip not in out:
            out.append(ip)
    return out


def _load(path: Path):
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = {str(i) for i in ext.value.get_values_for_type(x509.IPAddress)}
        return cert, ips
    except Exception:
        return None, set()


def _fp(cert) -> str:
    h = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def ensure_cert(extra_ips: Iterable[str] = (), force: bool = False) -> Tuple[Path, Path, List[str], str, bool]:
    """Retorna (crt, key, ips_no_SAN, fingerprint_sha256, regenerado).
    Reaproveita o certificado existente se ele ja cobre os IPs exigidos
    (os informados em --ip; senao, o IP principal detectado), para nao
    quebrar o 'pinning' embutido no app."""
    CERT_DIR.mkdir(exist_ok=True)
    detected = detect_local_ips()
    explicit = [str(ipaddress.ip_address(i)) for i in extra_ips]  # ValueError se invalido
    required = set(explicit) or {detected[0] if detected else "127.0.0.1"}

    cert, have = _load(CRT) if (CRT.exists() and KEY.exists()) else (None, set())
    now = datetime.datetime.now(datetime.timezone.utc)
    valid = cert is not None and (cert.not_valid_after_utc - now) > datetime.timedelta(days=30)

    if valid and not force and required <= have:
        return CRT, KEY, sorted(have), _fp(cert), False

    sans = {"127.0.0.1"} | set(detected) | set(explicit) | have
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SentinelMobile MVP"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SentinelMobile Local"),
    ])
    san_list = [x509.DNSName("localhost")] + [
        x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(sans)
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # autoassinado: emissor == titular
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, key_cert_sign=True,
                content_commitment=False, data_encipherment=False, key_agreement=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    KEY.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    CRT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return CRT, KEY, sorted(sans), _fp(cert), True