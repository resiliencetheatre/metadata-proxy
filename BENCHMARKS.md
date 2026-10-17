# Measurement methodology and baseline

This repository measures real Pure Ed25519 through libsodium, using the same
protocol functions as forwarding. No cryptographic stubs or unsigned production
mode exist. The results below are an initial microbenchmark baseline, not a
network forwarding capacity claim.

## Reproduce

```sh
make clean
make
./metadata-proxy bench --seconds 1 > results/micro.csv
# Longer microbenchmark: five seconds for each of six operations at each size
make bench
./metadata-proxy bench --seconds 5 --sizes 0,64,160,512,1024,1079
# Full loopback matrix: 3 paths × 2 sizes × 4 rates × 3 repetitions × 30 seconds
python3 tools/e2e.py --seconds 30 --repeats 3 \
  --rates 50,1000,10000,0 --sizes 64,1079 --output results/e2e.csv
# Short smoke test
python3 tools/e2e.py --seconds 1 --repeats 1 --output results/smoke.csv
```

`--seconds` for the C microbenchmark is a positive integer (default 5). It is
**per operation and payload size**, not the total run duration. Benchmark sizes
can range from 0 to 65386 for HOST-A. The UDP harness is IPv4 loopback only;
separate correctness integration covers IPv4 and IPv6 when sockets are permitted.

## Microbenchmark design

Each size has six rows:

| Operation | Work in timed loop |
|---|---|
| sign_only | Pure Ed25519 detached signing of pre-serialized domain/header/payload |
| verify_only | Pure Ed25519 verification of pre-serialized valid message |
| invalid_signature_verify | Same valid message, first signature byte changed |
| serialization_sign | Build contiguous domain/header/payload signing message, then sign |
| full_encapsulation | Encode fields, hash public key for ID, read realtime, copy payload, serialize and sign |
| decode_authorize_verify_freshness_replay | Parse, lookup/authorize key and label, verify, read realtime, freshness and replay update |

The full receive test has one trusted key and one replay-table slot; production's
larger session table is scanned linearly, so this is not a prediction of its
multi-session cost. There are no socket operations in these tests. Freshness
uses the same default 30-second age/5-second skew as production.

Each corpus has 128 independently signed packets with unique sequences 0..127
and a common session. Corpus preparation is outside verification timing. Each
complete verification pass resets its replay table **outside** timing so every
packet is accepted, not measured as a duplicate. If corpus timestamps age by
more than ten seconds or realtime moves backward, the corpus is re-signed outside
timing. At supported maximum size, corpus storage is bounded to 8,384,896 bytes;
at measured sizes it is 15,488–146,560 bytes, reported per row. One reusable
65,524-byte signing-message buffer and fixed-size structures are allocated before
timing. There are no timed heap allocations, keygen, key loading, corpus
preparation, replay resets, or console output.

Initial corpus signing and 64 verification warm-up operations precede timed work.
CLOCK_MONOTONIC brackets batches of 128 operations; two timing reads per batch
are included in the aggregate duration, not subtracted. The full construction
and receive paths also read CLOCK_REALTIME per operation as production does.
Reported ns/operation is elapsed batch time divided by operation count, **not**
a latency percentile. No percentiles or one-way/RTT claims are made.

Sequential rows run at different moments and may reflect CPU frequency changes
and competing work: a broader operation can occasionally appear faster than a
narrower one. These short, unpinned single-repeat measurements are not evidence
of a small performance difference. Preserve this baseline before optimization;
use longer repeats and controlled affinity for comparisons.

## UDP harness design

`tools/udp-traffic` is a C generator, sink, and explicitly benchmark-only plain
relay. There is no unsigned path in metadata-proxy. Paths are:

1. generator → sink (direct baseline);
2. generator → plain relay → plain relay → sink (matching socket/process hops);
3. generator → encap → decap → sink (signed).

The generator embeds a big-endian 64-bit sequence and deterministic validation
bytes. The sink validates expected length and bytes, tracks unique sequences in a bounded 32 MiB
bitmap, counts duplicates and packets arriving below the highest seen sequence.
The generator stops before sequence 2^28; excessively long trials may therefore
end early (the actual elapsed duration is reported). Payload sizes must be at
least eight bytes for this format. Protocol tests separately cover empty
payloads. The standard sizes include a small 64-byte payload and HOST-A's
maximum-fitting 1079 bytes under the 1200 cap.

Paced sends use absolute CLOCK_MONOTONIC deadlines; rate 0 means unpaced
saturation. A trial starts the sink and relays, allows 200 ms startup, runs the
generator, permits 300 ms drain, and terminates children gracefully. All waits
have deadlines and failures clean up children. Ports are selected dynamically;
there is a small bind race with unrelated local processes. A failed trial fails
the harness instead of creating a successful result row.

Raw CSV records requested rate, actual sent/received/lost counts, duplicates,
reordering, invalid data and send errors. `lost = successful sends − unique
validated receives`. Offered pps counts successful application sends per actual
generator duration; send errors are recorded separately. Goodput is received
original payload bytes × 8 / duration. Wrapper-inclusive throughput adds 121
bytes only to the signed path, per received packet. Neither throughput column
includes UDP/IP/Ethernet headers. Receiving fewer packets is not automatically
attributed to the cryptographic operation; socket/kernel/process bottlenecks
also matter. Proxy final counters are preserved in a companion process log.

Per-process user/system CPU seconds use wait4 resource usage: generator and sink
separately, plus the sum of both relays in CSV. Each relay’s individual CPU
seconds and command are also recorded in the process log. Total CPU utilization is
`100 × sum(user + system) / generator duration`: 100% means one fully occupied
core and the total can exceed 100%. CPU seconds include child startup/drain and
teardown; parent harness CPU is excluded. Loopback saturation shares the same
host CPU among generator, sink and both relays. It is not a NIC or remote-host
measurement. No latency measurement is implemented; remote one-way latency would
need aligned clocks and documented measurement points.

The environment sidecar records CPU, architecture, OS/kernel, compiler, libsodium,
affinity, sizes, duration and repeats. If custom build flags are used, pass CFLAGS
in the harness environment to record them accurately. Socket buffers retain OS
defaults; generator/sink actual SO_SNDBUF/SO_RCVBUF values are in CSV, and proxy
startup buffer values are in the process log. No affinity is imposed. `taskset`
may be used explicitly; its effective mask is recorded.

## Checks and execution limits in this environment

`make test` passed protocol/replay tests, independent OpenSSL-backed fixture
verification, key/configuration checks, and offline inspect tests. Protocol tests
include every byte of the fixed packet tampered, every truncation position,
10,000 bounded random parser inputs, all 256 label byte values, size bounds,
wrong keys, unauthorized labels, unknown IDs, freshness limits and replay window
boundaries including large jumps, cap exhaustion, expiry and clock movement.

`ASAN_OPTIONS=detect_leaks=0 make sanitize` passed those checks under ASan/UBSan.
The unmodified sanitizer invocation could not run LeakSanitizer under this
sandbox's tracing environment; **leak detection was not performed**. The regular
release build has been restored. Logs are in [results/test.log](results/test.log)
and [results/sanitize.log](results/sanitize.log).

This session prohibits UDP socket creation (`EPERM`). IPv4 and IPv6 integration
therefore explicitly skipped. The end-to-end harness also reports that restriction;
there are **no measured UDP throughput/loss/CPU results**, and the requested
30-second, three-repeat network trials could not run. Forwarding, PMTU options,
SIGTERM network cleanup, actual kernel-drop reporting, and the UDP harness still
need execution on a host with UDP sockets allowed. No network results are inferred
from the microbenchmark. The approval policy also rejected an attempt to run the
already-approved test target outside the sandbox; no network policy was bypassed.

## Recorded microbenchmark results

Host: AMD Ryzen 9 3950X 16-Core Processor, x86_64, Debian 13, kernel
`6.12.113+deb13-amd64`. GCC 14.2.0, libsodium 1.0.18,
`-O2 -g -std=c11 -Wall -Wextra -Wpedantic`, no affinity pinning.
One repetition, at least one timed second per row, CLOCK_MONOTONIC batch timing.
Full environment: [results/environment.json](results/environment.json).
Raw results: [results/micro.csv](results/micro.csv).

| Original bytes | Sign ops/s | Verify ops/s | Full receive ops/s | Full receive ns/op |
|---:|---:|---:|---:|---:|
| 0 | 58233 | 18985 | 19393 | 51565 |
| 64 | 62300 | 19407 | 19552 | 51145 |
| 160 | 59792 | 19910 | 19540 | 51176 |
| 512 | 56679 | 20341 | 17560 | 56946 |
| 1024 | 48088 | 19478 | 18802 | 53185 |

In this run signing took approximately 16.1–20.8 µs/operation
and verification 49.2–52.7 µs/operation. Verification is
the larger cryptographic cost here. These averages exclude sockets and network
loss; they must not be presented as end-to-end throughput. No optimization has
been justified from these short measurements alone.
