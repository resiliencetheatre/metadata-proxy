# metadata-proxy — implementation instructions

## Goal and scope

Implement a working minimal Linux UDP proxy in C, initially for Debian 13
amd64, with portable code suitable for future Buildroot Linux targets.
Use a simple Makefile and libsodium. Sign and verify EVERY encapsulated
datagram with Ed25519, so we can measure actual per-packet cryptographic cost.
Implement the prototype, tests, tools, and documentation; do not stop at a plan.

Each original UDP payload is encapsulated with visible cleartext metadata and
a detached signature. A receiving proxy verifies it, removes the wrapper, and
forwards exactly the original payload in one UDP datagram. Preserve empty
datagrams and datagram boundaries. Original IP/UDP headers, addresses, ports,
TTL, and checksums are not preserved. No payload encryption is added.

A primary goal is verifiable source attribution for third-party or multiple
observers, including DPI operators, passive monitors, and on-path intermediaries;
receiver authentication is one use case rather than the only purpose. Cleartext
metadata permits visual inspection, while per-packet signatures permit independent
cryptographic verification of endorsement and integrity. Publishing a host's public
key enables observers to verify its authorized labels once the key-to-host/label
association is established through a trusted channel. Source approval is an
observer policy decision. Publication alone is not proof of identity, and the
observed outer source address is not covered by the signature. Key distribution
and standalone DPI service integration remain outside v1; inspect and the optional
native Wireshark dissector support independent observer verification.

An observer with a trusted public key can verify an encrypted WireGuard
payload without decrypting it. The signature authenticates endorsement by a
key holder, not physical location, network path, original application identity,
clock correctness, or absence of relaying. Clear RTP stays clear.

Keep v1 deliberately small: static peers, fixed forwarding destinations,
software keys, one thread per process, no daemonization, no automatic discovery,
no certificates on the wire, no compression, no proxy fragmentation/reassembly,
no retransmission, no handshake, no batching of signatures, no unsigned mode,
no HMAC fallback, no custom cryptographic implementation.

## Build and structure

- C11 or C17; POSIX sockets and poll(); IPv4 and IPv6 via getaddrinfo().
- Runtime dependency: libsodium. Debian build packages: build-essential,
  pkg-config, libsodium-dev. Do not install packages without checking the environment.
- Makefile supports CC, CPPFLAGS, CFLAGS, LDFLAGS, LDLIBS and PKG_CONFIG
  overrides. Use pkg-config for libsodium; permit cross-compilation.
- Default warnings: -Wall -Wextra -Wpedantic. Provide make, make test,
  make bench, make sanitize, and make clean. No CMake, Rust, or mandatory Python
  runtime for the proxy. Optional test orchestration may use Python 3.
- Suggested layout: src/{main,protocol,keys,replay,stats}.c with small headers,
  tests/, tools/, Makefile, README.md, PROTOCOL.md, BENCHMARKS.md.
- Keep protocol encode/decode and verification independent of socket I/O.
- Avoid packed structs, unaligned loads, variable-length stack arrays,
  unbounded allocation, and allocation/key loading per packet.

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

## Keys and authorization

Provide `metadata-proxy keygen --secret FILE --public FILE`.
Use lowercase hexadecimal files: 32-byte Ed25519 seed (64 hex characters)
and 32-byte public key (64 hex characters), each followed by a newline.
Derive libsodium's signing secret key from the seed. Never confuse the seed
with libsodium's 64-byte secret-key representation.
Create new private files exclusively with mode 0600; do not overwrite existing
key files. Validate exact input lengths, handle I/O failures, never log secrets,
and zero secret material on cleanup using sodium_memzero().

Trust file: one `PUBLIC_KEY_HEX LABEL` entry per line, with blank lines and
whole-line # comments allowed. Each line authorizes that public key for exactly
that case-sensitive label. Multiple labels may reference one key. Derive key IDs
locally. Reject malformed configuration and collisions between distinct public
keys with the same 8-byte key ID. A key ID is a lookup hint, never a trust root.
No public keys supplied by incoming packets are trusted.

## Commands and forwarding topology

Implement and document these interfaces (including --help):

    metadata-proxy encap --listen HOST:PORT --peer HOST:PORT \
        --label HOST-A --secret FILE [--max-datagram 1200] [--stats-interval 5]
    metadata-proxy decap --listen HOST:PORT --forward HOST:PORT \
        --trust FILE [--max-datagram 1200] [--max-age-ms 30000] \
        [--future-skew-ms 5000] [--max-sessions 1024] [--stats-interval 5]
    metadata-proxy inspect --packet FILE --trust FILE
    metadata-proxy bench [--seconds 5] [--sizes 0,64,160,512,1024]

Require bracketed IPv6 endpoints, e.g. [::1]:5000. Resolve endpoints at startup.
Inspect reads one binary outer UDP payload, not a pcap. Report structural
validity, known key, authorized label, signature validity, and timestamp;
offline age is informational. It does not claim replay protection.
Document extraction of a UDP payload from a capture for inspection.

First implement each direction as a separate process. Bidirectional traffic
uses two independently signed directions with distinct session IDs. Explain
the necessary port mapping and provide a concrete two-host example with
separate local application input/output ports. Do not imply these fixed-peer
commands automatically support arbitrary clients, dynamic replies, or
transparent bidirectional WireGuard endpoint learning. Document any extra
socket multiplexing needed for a real WireGuard arrangement as a later step.
Restrict local encapsulation listeners to loopback in examples; any process
able to submit to that listener can ask the proxy to endorse payloads.

Use normal UDP sockets; no root, raw sockets, TUN device, or firewall changes.
Support graceful SIGINT/SIGTERM with final statistics. Handle EINTR, EAGAIN,
socket errors, and send failures. No packet-by-packet logging by default.
Use recvmsg() and detect MSG_TRUNC; never forward a truncated payload.

## Freshness and replay protection

Decap forwards only structurally valid, authorized, signature-valid, fresh,
non-replayed packets. Authenticate before creating/updating replay state.
Check time safely without unsigned subtraction underflow: default age <=30 s,
future skew <=5 s. Time is a sender assertion; require reasonably synchronized
clocks. Use CLOCK_MONOTONIC for durations and CLOCK_REALTIME for wire time.
Fail with a clear error if local realtime is unusable; document clock steps.

Replay state is keyed by full trusted public key and session ID. Maintain a
1024-packet bitmap sliding window: accept unseen reordered sequences within
the window, reject duplicates and older sequences. Update state before
forwarding so a forwarding error cannot make a replay acceptable.
Limit sessions to the configured cap; reject new sessions when full rather
than evicting live replay protection. Retain each session until its latest
authenticated accepted timestamp plus max-age has expired under the current
clock. Do not let reordered older timestamps shorten retention. Test boundary
conditions and document behavior on realtime clock changes.
No replay-state persistence in v1: explicitly document that receiver restart
can permit replay of packets still inside the freshness window. Stateless
observers cannot prove a captured packet has never appeared elsewhere.

## Size and MTU policy

--max-datagram is the total outer UDP payload cap, default 1200, not an IP MTU
and not the inner payload cap. Hard cap 65507 for v1 on either address family.
For HOST-A, default maximum original payload is 1079 bytes. Reject an input
that cannot fit; count it and continue. Decap enforces its configured cap too.
Never silently truncate, split, retry smaller, or remove the signature.

For path MTU 1500, no IPv4 options/IPv6 extensions, HOST-A budgets are 1351
original bytes over IPv4 and 1331 over IPv6. Explain that WireGuard's own
encapsulation further reduces its inner interface MTU. Default 1200 is
conservative, not a universal path guarantee. On Linux request no IP
fragmentation using suitable IPv4/IPv6 socket options; handle EMSGSIZE and
document that no automatic PMTU discovery/adaptation is implemented.

## Measurement is a primary deliverable

Use the same serialization, signing, and verification functions in benchmarks
and real forwarding. Never replace cryptography with a stub in signed tests.
No hard-coded performance claims; report actual measured values or clearly
state why a measurement could not run.

1. In-process microbenchmarks: pre-serialized-message sign-only, verify-only,
   serialization+sign, and full decode+authorization+verify+freshness+replay.
   Also measure full encapsulation construction. For replay benchmarks generate
   valid unique sequences and signatures outside the timed verification loop;
   do not accidentally measure duplicate rejection. Bound corpus memory, report
   corpus size and reuse/reset policy. Test invalid-signature verification too.
2. Use monotonic timing, warm-up, configurable run duration, and report operations/s,
   ns/operation, message size, label size, and allocation policy. Exclude keygen,
   key loading, packet corpus preparation, and console output from timed loops.
   Batch timing to avoid one clock syscall dominating each crypto operation.
3. Provide a C UDP traffic generator/sink and a repeatable end-to-end harness:
   generator -> encap -> decap -> sink. Payloads carry sequence numbers and
   validation bytes; verify contents and measure sent/received/lost/duplicate/
   reordered counts. Include small and maximum-fitting payloads.
4. Compare direct UDP, an explicitly named benchmark-only plain UDP relay path
   with matching process/socket hops, and the signed proxy path. Plain relays
   must not be a decap fallback or an unsigned production protocol mode.
5. Sweep paced rates (including voice-like 50 packets/s and increasing loads),
   then measure saturation. Run 30-second trials with three repeats where the
   environment permits; expose duration/rate controls for shorter smoke tests.
   Report offered load, achieved goodput, wrapper-inclusive throughput, loss,
   process user/system CPU seconds and CPU utilization convention. State that
   loopback saturation shares CPU with generator and sink.
6. Report per-operation latency percentiles only with a stated sampling method
   and timing overhead; throughput and ns/operation are required. Do not call
   RTT one-way latency. Network one-way measurements require clock alignment;
   local tests may use a shared host monotonic clock with documented placement.
7. Record CPU model, architecture, OS/kernel, compiler/version/flags, libsodium
   version, affinity if used, payload size, socket buffers, duration, repetitions,
   and clock source. Include reproducible commands and raw CSV results.

Periodic/final counters distinguish input packets/bytes, forwarded packets/
bytes, oversize, truncation, parse errors, unknown keys, unauthorized labels,
invalid signatures, stale/future packets, replay drops, session-cap drops,
socket errors, send failures, and kernel receive drops where available
(SO_RXQ_OVFL). Make accounting stages explicit; application success on send
does not establish delivery. Use 64-bit counters and no hot-path printing.
Do not add per-packet timing overhead to production forwarding by default.

## Required correctness checks

- Independent deterministic wire fixture with fixed seed/session/time/sequence:
  verify exact offsets, lengths, endian encoding, signature, and payload.
  Cross-check a fixture using an independent binding/tool when available.
- Round trips: empty, binary NUL-containing, RTP-like, WireGuard-like opaque
  payloads, configured size boundary, maximum label, IPv4 and IPv6.
- Tamper each metadata field, label, signature, and payload; reject invalid
  packets without forwarding. Test wrong key, valid signature with unauthorized
  label, unknown key, malformed config, trailing data, and truncated datagrams.
- Replay tests: duplicate, reordering, bitmap/window boundaries, large sequence
  jumps, separate sessions/keys, expiry, table exhaustion, receiver restart,
  timestamp boundaries, future skew, and simulated clock movement.
- Parser tests for every truncation point, inconsistent lengths, invalid label
  bytes, and unsupported versions/flags; run under ASan/UBSan.
- Integration: verify one output datagram per accepted input and byte-for-byte
  preservation; invalid inputs produce none. Test IPv6 when supported and
  report an explicit skip otherwise. Tests must use timeouts and clean up children.

## Documentation and completion

README includes Debian build/run commands, key/trust setup, two-host topology,
IPv4/IPv6 examples, capture/inspection, MTU arithmetic, clock/replay limitations,
cleartext visibility, and benchmark invocation. PROTOCOL.md mirrors this wire
format exactly. The optional native Wireshark dissector verifies signatures using libsodium;
distinguish display decoding from actual cryptographic verification.

Implement in order: protocol/keys + fixtures; forwarding + trust/replay;
integration/sanitizers; microbenchmarks + UDP harness; measurements and docs.
Keep changes focused and inspect any existing repository instructions first.
Never commit generated private keys or claim tests/benchmarks that were not run.
Conclude with implemented behavior, actual checks/results, performance findings,
and remaining limitations. Optimize only after retaining a measured baseline.
