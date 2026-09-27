"""
TLS cipher suite lookup (IANA TLS Cipher Suite Registry subset covering
suites actually seen in modern SMTP/IMAP/POP3-over-TLS deployments).

Maps the hex code negotiated in ServerHello to:
  - name              human-readable cipher suite name
  - key_exchange      key exchange mechanism (ECDHE, DHE, RSA, PSK, ...)
  - authentication     auth mechanism (RSA, ECDSA, PSK, N/A for TLS1.3)
  - forward_secrecy   True if the key exchange is ephemeral (ECDHE/DHE),
                       or the suite is TLS 1.3 (which is FS-only by design)

Unknown codes return a conservative "UNKNOWN" record rather than a guess.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class CipherSuiteInfo:
    code: str
    name: str
    key_exchange: str
    authentication: str
    forward_secrecy: bool


# TLS 1.3 suites (RFC 8446) -- key exchange is negotiated separately via the
# key_share extension (always ephemeral: X25519/secp256r1/etc.), so these
# are forward-secret by construction.
_TLS13_SUITES = {
    "0x1301": ("TLS_AES_128_GCM_SHA256", "ECDHE/DHE (key_share)", "N/A"),
    "0x1302": ("TLS_AES_256_GCM_SHA384", "ECDHE/DHE (key_share)", "N/A"),
    "0x1303": ("TLS_CHACHA20_POLY1305_SHA256", "ECDHE/DHE (key_share)", "N/A"),
    "0x1304": ("TLS_AES_128_CCM_SHA256", "ECDHE/DHE (key_share)", "N/A"),
    "0x1305": ("TLS_AES_128_CCM_8_SHA256", "ECDHE/DHE (key_share)", "N/A"),
}

# TLS 1.2 and earlier suites: (name, key_exchange, authentication, forward_secrecy)
_LEGACY_SUITES = {
    "0xC02F": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", True),
    "0xC030": ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", True),
    "0xC02B": ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", True),
    "0xC02C": ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", True),
    "0xCCA8": ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", True),
    "0xCCA9": ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", True),
    "0xC013": ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", True),
    "0xC014": ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", True),
    "0xC009": ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", True),
    "0xC00A": ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", True),
    "0x009E": ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", True),
    "0x009F": ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", True),
    "0x0033": ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", True),
    "0x0039": ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", True),
    # Static RSA key exchange -- NOT forward secret (session key derivable if
    # the server's long-term private key is ever compromised)
    "0x009C": ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", False),
    "0x009D": ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", False),
    "0x002F": ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", False),
    "0x0035": ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", False),
    "0x003C": ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", False),
    "0x003D": ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", False),
    "0x000A": ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", False),
    # Explicitly weak / export-grade -- included so the rule engine can name them
    "0x0004": ("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", False),
    "0x0005": ("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", False),
    "0x0000": ("TLS_NULL_WITH_NULL_NULL", "NULL", "NULL", False),
}


def lookup_cipher_suite(hex_code: Optional[str]) -> Optional[CipherSuiteInfo]:
    """hex_code like '0xC02F'. Returns None if hex_code is None (not observed)."""
    if not hex_code:
        return None
    # Normalize to '0x' + uppercase hex digits without upper()-ing the 'x' itself
    # (naive .upper() turns '0x...' into '0X...' and breaks the dict lookup below).
    digits = hex_code[2:] if hex_code[:2].lower() == "0x" else hex_code
    code = "0x" + digits.upper()

    if code in _TLS13_SUITES:
        name, kx, auth = _TLS13_SUITES[code]
        return CipherSuiteInfo(code=code, name=name, key_exchange=kx, authentication=auth, forward_secrecy=True)

    if code in _LEGACY_SUITES:
        name, kx, auth, fs = _LEGACY_SUITES[code]
        return CipherSuiteInfo(code=code, name=name, key_exchange=kx, authentication=auth, forward_secrecy=fs)

    return CipherSuiteInfo(code=code, name=f"UNKNOWN ({code})", key_exchange="UNKNOWN", authentication="UNKNOWN",
                            forward_secrecy=False)  # conservative: unrecognized suite is not assumed forward-secret
