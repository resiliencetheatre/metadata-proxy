# metadata-proxy wire protocol

## Wire protocol v1 (normative)

Every outer UDP payload has this exact layout. All numeric fields are unsigned
big-endian integers. Offsets are zero based. No optional fields or padding.

| Offset | Size | Field | Rule |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII MDPX |
| 4 | 1 | version | 1 |
| 5 | 1 | flags | 0; reject any other value |
| 6 | 2 | header_length | 115 + label_length, including signature |
| 8 | 1 | label_length | 1..63 |
| 9 | 2 | payload_length | exact original UDP payload length |
| 11 | 8 | key_id | first 8 bytes of SHA-256(raw 32-byte public key) |
| 19 | 8 | timestamp_ms | Unix epoch milliseconds from CLOCK_REALTIME |
| 27 | 16 | session_id | fresh cryptographic random bytes per sender start |
| 43 | 8 | sequence | starts at 0; increment per generated packet |
| 51 | L | label | L ASCII bytes; no terminating NUL |
| 51+L | 64 | signature | detached Ed25519 signature |
| 115+L | P | original_payload | P unmodified bytes |

Labels permit only [A-Za-z0-9._-], with case-sensitive authorization. HOST-A
is six bytes, giving a 121-byte wrapper. Restrict labels before signing and
while parsing. Reject unknown versions, reserved flags, invalid labels,
inconsistent lengths, truncation, and trailing bytes. Perform overflow-safe
length calculations before accessing fields. Zero-length payloads are valid.

The exact Ed25519 message is:

    ASCII("metadata-proxy/v1") || packet[0 : 51+L] || original_payload

The ASCII domain prefix is exactly 17 bytes, without a NUL. Slice notation is
half-open. The signature field is excluded. Use libsodium's standard
crypto_sign_detached()/crypto_sign_verify_detached() (Pure Ed25519), not
Ed25519ph, a custom prehash, or a truncated signature. Construct the message
in a reusable bounded buffer. A signature covers all metadata and payload.
Use sodium_init(), randombytes_buf(), and the library's primitives.
Abort/restart the session before sequence wrap; never reuse a session after
restart. A send failure may leave sequence gaps; that is acceptable.

## Receiver processing

1. Enforce configured outer cap (hard limit 65507) and reject MSG_TRUNC.
2. Parse exact lengths, version, flags and label restrictions above.
3. Find locally trusted key ID and exact authorized label; authenticate the
   detached signature with the associated full public key.
4. Accept timestamps at most max-age milliseconds old or future-skew
   milliseconds ahead. Default bounds are 30000 and 5000, inclusive.
5. Update the per-full-public-key/session 1024-bit replay window before forwarding.
6. Send exactly P original bytes as one UDP datagram, including P=0.

No optional wire fields exist. Key ID is the first eight digest bytes (not
host-endian numeric reinterpretation). Session ID is 16 opaque random bytes.
A new sender starts at sequence zero with a fresh session. It stops before
sequence wrap. Labels are case-sensitive. The detached signature is 64 bytes;
standard Pure Ed25519 is used, not Ed25519ph. No unsigned form is accepted.

Trust files authorize raw 32-byte public keys locally; no keys or certificates
are carried in packets. This format authenticates endorsement, not location,
path, clock truth, original sender identity, or proof against relaying.

The independent deterministic fixture in tests/fixture.hex uses seed 00..1f,
session a0..af, timestamp 0x0000018bcfe56800, sequence 0x0102030405060708,
label HOST-A and payload 00010203. Its total length is 125 bytes. The optional
tests/fixture.py reconstructs it using Python cryptography/OpenSSL, independent
of the production libsodium serialization and signing implementation.

## Independent observer verification

Third-party and multiple-observer verification is a primary purpose of this
format. A DPI operator, passive monitor, or on-path intermediary can read the
cleartext metadata and verify the signature without decrypting an encrypted
original payload or participating in the receiver's forwarding operation.
Each observer needs the complete outer UDP payload and a trusted association
between the published public key, its permitted labels, and the identified
source. No private signing material is needed by observers.

Observers perform structural validation, trusted key lookup, label authorization,
and Pure Ed25519 verification using the same message definition above. Merely
displaying the label or recognizing the key ID is not verification. Publishing
a key does not by itself authenticate its association with a host; establishing
that association and deciding whether the source is approved are external trust
and policy decisions. No key distribution or certificates are added to v1.

Successful verification proves integrity of the metadata and payload and
endorsement by the trusted key holder. The outer IP/UDP headers are not signed:
a key-to-host inventory does not make the observed network source address a
cryptographic proof of origin. Relaying and replay do not invalidate a signature.
Freshness and duplicate detection require each observer's own clock policy and
state; a stateless observer cannot prove global uniqueness or receiver acceptance.
Multiple observers may independently validate the same signed packet.
