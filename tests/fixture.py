#!/usr/bin/env python3
"""Independent fixture verification (optional Python cryptography/OpenSSL binding)."""
import hashlib,pathlib,struct
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
except ImportError:
    print('SKIP independent fixture cross-check: Python cryptography unavailable')
    raise SystemExit(0)
key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
pk=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
head=b'MDPX'+bytes([1,0])+struct.pack('>HBH',121,6,4)+hashlib.sha256(pk).digest()[:8]+struct.pack('>Q',0x18bcfe56800)+bytes(range(0xa0,0xb0))+struct.pack('>Q',0x0102030405060708)+b'HOST-A'
payload=bytes(range(4));sig=key.sign(b'metadata-proxy/v1'+head+payload)
expected=bytes.fromhex(pathlib.Path(__file__).with_name('fixture.hex').read_text())
assert expected==head+sig+payload
key.public_key().verify(expected[57:121],b'metadata-proxy/v1'+expected[:57]+expected[121:])
print('independent OpenSSL-backed Ed25519 fixture passed')
