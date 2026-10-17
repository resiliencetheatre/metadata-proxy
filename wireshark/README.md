# MDPX Wireshark dissector and signature verifier

This native C plugin displays MDPX v1 fields and verifies every complete,
structurally valid packet for which a trusted public key is configured. It uses
the project's existing protocol parser, trust-file parser and libsodium Pure
Ed25519 verifier. It does not run external commands or implement custom crypto.
It works in Wireshark and TShark, for saved captures or live dissection.

The plugin is optional. Building the proxy does not require Wireshark headers.
Linux/Debian 13 and Wireshark/TShark **4.4.19** were tested. Build against the
same Wireshark major/minor version used to load the plugin; rebuild when that
version changes. The plugin exports Wireshark's required version markers.

## Build and install

From the project root, check dependencies first:

```sh
wireshark --version
pkg-config --modversion wireshark libsodium
command -v tshark
```

If missing, Debian packages are:

```sh
sudo apt-get install build-essential pkg-config libsodium-dev libwireshark-dev tshark
```

TShark is used by the tests and the installation-directory query below. You do
not need to enable privileged capture to use it on saved captures.

```sh
make wireshark
make test-wireshark
```

Close Wireshark before installing or replacing the plugin. Find its personal
**binary** plugin directory, which includes its major/minor version:

```sh
tshark -G folders
```

For Wireshark 4.4 on a default Linux account it is usually
`~/.local/lib/wireshark/plugins/4.4`. Use the path actually printed for
`Personal Plugins`, not the `Personal Lua Plugins` path. To install automatically
using that output:

```sh
mdpx_plugin_dir="$(tshark -G folders | awk -F '\t' '/^Personal Plugins:/ {print $2}')"
if [ -n "$mdpx_plugin_dir" ]; then
    install -Dm755 wireshark/mdpx.so "$mdpx_plugin_dir/epan/mdpx.so"
fi
```

Reopen Wireshark. **Help → About Wireshark → Plugins** should list `mdpx.so`,
version `1.0.0`. You can also check:

```sh
tshark -G plugins | grep mdpx
```

Install only one copy per Wireshark installation; remove an old display-only
MDPX Lua dissector if one was installed separately. Do not run Wireshark as root.
To uninstall, close Wireshark and remove only the installed `epan/mdpx.so` file.

The Makefile supports `CC`, `PKG_CONFIG`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS`,
and explicit `WS_CFLAGS`, `WS_LIBS`, `SODIUM_CFLAGS`, `SODIUM_LIBS` overrides for
SDK/extracted-header builds. `make clean` removes the built plugin, not an
installed copy. No CMake or Wireshark source rebuild is needed.

## Configure desk and dell

Combine the existing public trust entries:

```sh
cat trust-a.txt trust-b.txt > observer-trust.txt
```

Or create the file directly from the public key files:

```sh
awk '{print $0 " HOST-A"}' host-a.public > observer-trust.txt
awk '{print $0 " HOST-B"}' host-b.public >> observer-trust.txt
```

These alternatives produce the same mappings: HOST-A for desk and HOST-B for
dell. Provision this public material through a trusted channel. The observer
never needs `host-a.secret` or `host-b.secret`.

In **Edit → Preferences → Protocols → MDPX**, configure:

- **Public-key trust file:** absolute path to `observer-trust.txt`.
- **UDP port:** `5200` by default. Use another port for a different deployment;
  `0` disables automatic port binding. Values above 65535 also disable binding.

For traffic on another port, **Analyze → Decode As → UDP port → MDPX** is also
supported. The port association applies to packets using that source or
destination port; other protocols on that port will be reported as malformed
MDPX unless the association is disabled or changed.

Trust is loaded at startup/preference application and when opening a capture.
**After editing the file in place, reopen the capture or restart live capture.**
There is no per-packet disk access or automatic key-file watcher. Configuration
errors clear the whole trust table, rather than retaining previous or partially
loaded keys. The existing trust format permits blank lines and whole-line `#`
comments, 4096 entries, and bounded lines of at most 511 bytes including newline.
Malformed entries, embedded NULs, invalid labels, and conflicting key IDs are
rejected. The public key is never taken from packet data.

## Display and filters

Expand **Metadata Proxy** in the packet details. All wire fields are exposed:
magic, version, flags, header/label/payload lengths, key ID, Unix timestamp in
milliseconds, session ID, sequence, label, detached signature, and original
payload. Sequence and timestamp retain their full unsigned 64-bit precision.
Partial captures display only fields actually available.

Generated verification fields are clearly separate from bytes on the wire:

| Field | Meaning |
|---|---|
| `mdpx.capture_complete` | Entire reported UDP payload was captured |
| `mdpx.structure_valid` | Exact v1 format/length/label validation passed; absent for incomplete capture |
| `mdpx.known_key` | Key ID matched a configured full trusted public key |
| `mdpx.authorized` | That key is authorized for this exact case-sensitive label |
| `mdpx.signature_valid` | Actual Pure Ed25519 verification result |
| `mdpx.status` | Overall result code below |

**Absent verification fields mean “not checked,” not false.** For example,
`signature_valid` is absent for an unknown key, an incomplete capture, a malformed
packet, or a trust configuration problem. A known key's signature is checked
even when the label is unauthorized. `authorized=true` alone is not proof:
metadata may have been tampered with, so also require `signature_valid=true`.

```text
mdpx
mdpx.label == "HOST-B"
mdpx.signature_valid == true && mdpx.authorized == true
mdpx.signature_valid == false
mdpx.known_key == false
mdpx.authorized == false
mdpx.capture_complete == false
mdpx.status == 7
```

Right-click a generated field and select **Apply as Column** to see results in
the packet list. The Info column also reports the label, sequence, length and
verification result. Expert Information flags malformed packets, truncation,
unknown/unconfigured keys, configuration errors, invalid signatures, and valid
signatures with unauthorized labels.

| `mdpx.status` | Result |
|---:|---|
| 0 | Valid signature and authorized label |
| 1 | Invalid signature under the configured key |
| 2 | Unknown key; verification unavailable |
| 3 | Valid signature, unauthorized label |
| 4 | Malformed MDPX structure |
| 5 | Incomplete capture |
| 6 | No trust file configured |
| 7 | Trust file unreadable or malformed |
| 8 | Cryptographic initialization failed |

An empty original datagram is valid and still has the MDPX wrapper. An entirely
empty outer UDP payload has no wrapper; Wireshark may not call any subdissector
for it. Likewise, captures cut off before UDP dispatch may have no MDPX fields
at all. Absence of MDPX fields is never successful verification.

## TShark examples

Read a capture using both hosts' public keys:

```sh
tshark -n -r capture.pcapng \
  -o "mdpx.trust_file:$PWD/observer-trust.txt" \
  -Y mdpx -T fields \
  -e frame.number -e mdpx.label -e mdpx.key_id \
  -e mdpx.signature_valid -e mdpx.authorized -e mdpx.status
```

Show only cryptographically valid, authorized packets:

```sh
tshark -n -r capture.pcapng \
  -o "mdpx.trust_file:$PWD/observer-trust.txt" \
  -Y 'mdpx.signature_valid == true && mdpx.authorized == true'
```

Decode a nonstandard UDP port without automatically binding 5200:

```sh
tshark -n -r capture.pcapng -o mdpx.udp_port:0 \
  -d udp.port==6200,mdpx \
  -o "mdpx.trust_file:$PWD/observer-trust.txt" -Y mdpx
```

## Verification boundaries and performance

The signature covers `"metadata-proxy/v1" || metadata || original_payload` with
the exact serialization in [PROTOCOL.md](../PROTOCOL.md). It requires the entire
payload, including encrypted bytes for WireGuard. No payload decryption occurs.
Capturing only the metadata is insufficient. Wireshark's IP reassembly must
produce a complete UDP payload if incoming traffic was fragmented.

This is **stateless authenticity verification**, not the receiver's admission
policy. Historical timestamps and repeated packets retain a valid signature.
The plugin does not enforce freshness or maintain replay state, and cannot prove
physical origin, network path, the outer source IP, or destination acceptance.
It proves endorsement by the configured key holder; approval of that identity is
the observer's policy. Anyone holding the corresponding private key can sign.

Verification is recomputed on redissection; no result cache can retain a verdict
from old trust settings. Captures with many packets therefore incur repeated
cryptographic cost when filters or preferences change. There are no per-packet
process launches or key loads, and fixed reusable buffers bound protocol work.
The shared trust table and buffer follow Wireshark's serialized dissector model.
No live throughput claim is made from these offline tests.

## Tests and validation

`make test-wireshark` runs real TShark in a temporary plugin/configuration
directory, never writing to your personal Wireshark directory. It requires
Python 3, libsodium and TShark; the Python standard library's ctypes signs only
additional fixed-seed test data. No generated private-key files are created.
`TSHARK=/path/to/tshark` selects another matching executable.

Tests cover plugin loading; the independent deterministic fixture; every-byte
tampering and every truncation point; IPv4 and IPv6 captures; empty, binary,
maximum label and maximum outer payload; unknown keys; unauthorized labels;
missing/malformed trust; exact 64-bit values; duplicate/historical packets;
configurable port and Decode As; display filters; and two-pass redissection.
Only the expected absent-dispatch cases for an empty outer payload or no
captured UDP payload are exempted from requiring a plugin result.

The implementation follows Wireshark's
[dissector API](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html)
and [plugin registration model](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterPlugins.html).

Validation performed for this change: the complete offline suite passed with
Wireshark/TShark 4.4.19, GCC 14.2.0 and libsodium 1.0.18, both as a release build
and with the plugin/core instrumented by ASan/UBSan. TShark itself was the distro
binary, not rebuilt with sanitizers. Leak detection was disabled because this
environment runs under tracing. GUI interaction and live capture were not tested;
these use the same dissector tested offline. The proxy regression suite also
passed its non-network tests; its UDP tests still explicitly skip under the
socket-restricted environment.

To reproduce plugin instrumentation with GCC and installed development headers:

```sh
make -C wireshark clean
make -C wireshark CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined'
ASAN_OPTIONS=detect_leaks=0 \
  MDPX_TEST_PRELOAD="$(cc -print-file-name=libasan.so)" \
  python3 tests/wireshark.py
# Restore the release plugin before installing it:
make -C wireshark clean
make wireshark
```

The test harness preloads ASan into its TShark children only. `MDPX_PLUGIN` may
select a separately built instrumented plugin instead of `wireshark/mdpx.so`.
