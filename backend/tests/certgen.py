"""
Certificate Test Lab (sections 37-38).

Generates certificates entirely locally for deterministic, known-ground-
truth test fixtures. NEVER commit the private keys this produces at scale;
these are ephemeral, in-memory, test-only keys regenerated on every run.
"""
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID


def _build_name(cn: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_self_signed_cert(cn: str, days_valid: int = 365, not_before_days_ago: int = 1, key_size: int = 2048):
    """
    days_valid > 0  -> not_after is in the future (valid or not-yet-valid window)
    days_valid < 0  -> not_after is in the past (expired), abs(days_valid) days ago
    not_before_days_ago negative -> not_before is in the future (not-yet-valid)
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = _build_name(cn)
    not_before = datetime.datetime.utcnow() - datetime.timedelta(days=not_before_days_ago)
    if days_valid > 0:
        not_after = not_before + datetime.timedelta(days=days_valid)
    else:
        not_after = datetime.datetime.utcnow() - datetime.timedelta(days=abs(days_valid))

    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), key


def make_ca_signed_cert(cn: str, key_size: int = 2048):
    """Returns (leaf_der, ca_der) -- leaf issued by a freshly generated test CA."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    ca_name = _build_name("Demo Test Root CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    leaf_name = _build_name(cn)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name).issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf_cert.public_bytes(serialization.Encoding.DER),
        ca_cert.public_bytes(serialization.Encoding.DER),
    )


# --------------------------------------------------------------------- #
# Richer fixtures for cryptographic chain-validation and revocation
# tests: real root/intermediate/leaf hierarchies with AKI/SKI, and
# optional AIA (OCSP) / CRL Distribution Point extensions on the leaf.
# --------------------------------------------------------------------- #

def make_root_ca(cn: str = "Test Root CA", key_size: int = 2048):
    """Returns (der, private_key, x509.Certificate) for a self-signed root."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = _build_name(cn)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), key, cert


def make_intermediate_ca(cn: str, issuer_cert, issuer_key, key_size: int = 2048):
    """Returns (der, private_key, x509.Certificate), signed by issuer_cert/issuer_key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = _build_name(cn)
    issuer_ski = None
    try:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        pass
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer_ski is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski), critical=False,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER), key, cert


def make_leaf_cert(cn: str, issuer_cert, issuer_key, *, key_size: int = 2048,
                    ocsp_url: str = None, crl_url: str = None):
    """Returns (der, private_key, x509.Certificate), signed by issuer_cert/issuer_key.
    Optionally embeds an AIA/OCSP and/or CRL Distribution Point extension
    so revocation.py has something to find."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = _build_name(cn)
    issuer_ski = None
    try:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        pass
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer_ski is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski), critical=False,
        )
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)),
            ]), critical=False,
        )
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None,
                ),
            ]), critical=False,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER), key, cert


def tamper_signature(der_bytes: bytes) -> bytes:
    """Flips the last byte of the DER encoding, which (for a
    well-formed cert) lands inside the signature value and makes
    cryptographic verification fail while leaving the cert otherwise
    parseable."""
    b = bytearray(der_bytes)
    b[-1] ^= 0xFF
    return bytes(b)


def make_fake_trust_store(root_cert):
    """Builds a chain_validation.TrustStore containing exactly one root,
    for tests that need a deterministic local trust anchor without
    touching the real certifi bundle."""
    import hashlib
    from app.parsing.chain_validation import TrustStore

    der = root_cert.public_bytes(serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()
    subject = root_cert.subject.rfc4514_string()
    store = TrustStore()
    store.by_subject[subject] = [root_cert]
    store.by_fingerprint[fp] = root_cert
    store.count = 1
    return store
