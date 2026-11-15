# seedstore: performance

Numbers and tuning notes for the [WASM implementation](../WASM/README.md). Spec
references (`§n`) point to [SPEC.md](SPEC.md). Run the commands from `WASM/` after
`npm run build`.

## The codec

100 MB, RS(10,6), 64 KB blocks, single-threaded (Node 24), measured with
`node tests/bench.mjs`:

| | time | rate | |
|---|---:|---:|---|
| **write**: full (encrypt + hash + RS encode) | ~0.35 s | ~284 MB/s | |
| &nbsp;&nbsp;↳ AES-256-GCM seal | ~0.09 s | ~1.1 GB/s | the detached tag lives in the descriptor |
| &nbsp;&nbsp;↳ RS encode (SIMD) | ~0.07 s | ~1.3 GB/s | |
| &nbsp;&nbsp;↳ SHA-256 block ids | ~0.16 s | ~980 MB/s | hashes all *n* blocks (1.6×) |
| **read**: all data present (systematic) | ~0.04 s | ~2.7 GB/s | the common path: a concat, no GF math |
| **read**: one block missing (decode, SIMD) | ~0.06 s | ~1.6 GB/s | the common failure, §6/§21 |

**The seal and the hash are the platform's.** AES-256-GCM and SHA-256 run on the CPU's
AES and SHA instructions (here OpenSSL, as on every Node, and Go on native), the same
primitives the guest reaches through `crypto/*`. A page seals with WebCrypto and hashes
with the libsodium its host blob carries. RS encode is ~8% slower on Node 24 than on
Node 20 or 22, because V8 13 rebuilds the SIMD mask constant at every use; loading the
mask from memory wins that back.

Three optimizations got the codec here:

1. **A 256×256 GF(2⁸) multiply table**: one indexed load per byte, which made encode
   **~26× faster** than the naive exp/log multiply.
2. **SHA-256 block ids instead of SHA-3**: **~5× faster**. SHA-3 was originally the
   write bottleneck at ~0.83 s. SHA-256 is the host's own, so it adds no bytes (§16).
3. **WASM SIMD for the RS multiply-accumulate loops**: another **~3.4×** on encode and
   decode.

With all three, the block ids are the largest part of a write, and reads spend nothing
in the codec unless a block is actually missing. SIMD needs a runtime with the WASM simd
feature, which means Node 16+ or any current browser.

**The SIMD split-table trick (GF(2⁸) "PSHUFB").** For a fixed coefficient *c*, `c·x`
splits into two 4-bit lookups, `c·(x & 0x0F) ⊕ c·(x >> 4)`, each from a 16-byte table.
WASM's `i8x16.swizzle` does 16 table lookups in parallel, so one instruction multiplies
16 bytes. Output accumulators stay in `v128` registers across the *k* inputs (register
blocking), and a scalar tail handles a block whose size isn't a multiple of 16. Native
RS libraries use the same technique.

**Block-id hash: SHA-256.** Block ids are internal to storage and never cross into the
host, so the hash is storage's own choice, and SHA-256 is the one the host already
computes. A tree hash's *interior nodes* (BLAKE3's chaining values, say) would **not**
work as block ids. Content-addressed ids must be position-independent, because a holder
re-verifies `hash(bytes) == id` with no context (§4.2). BLAKE3 chaining values depend on
position, and using them would bring back the Merkle-path machinery the spec avoids
(§8).

## End to end: the link is the limit

Once a file spans many blocks, the link bounds throughput, not the codec. The
coordinator batches blocks into records of up to `maxMessageBytes`. WebRTC physical
messages stay capped at 48 KiB, but the channel adapter exposes a length-framed byte
stream, so a 256 KiB record is split and reassembled without an extra round trip.

### Modelled latency (`bench-net.mjs`)

Node 24, 10 ms RTT, 4 MB, RS(2,2), 32 KiB blocks, 256 KiB batches in 48 KiB physical
messages, window 32 (`node tests/bench-net.mjs 10 4 32 256 48 32`; leave off the
final `32` to sweep the window):

| | time | rate | |
|---|---:|---:|---|
| **PUT** | ~0.29 s | ~14.0 MB/s | ships the 2× erasure overhead: RS(2,2) is 2 data + 2 parity |
| **GET** | ~0.16 s | ~25 MB/s | downloads any *k* of *n*, i.e. 1× the file |

The bench applies latency at the wire. Every message pays it in both directions, so one
request/response costs a full RTT. The physical chunks of one message share a single
delivery delay, as they would on an ordered byte stream. Its nodes run on Node's own AES
and SHA-256. On a page's crypto, AES on WebCrypto, which answers a turn later, and
SHA-256 on the host's libsodium, the same run is PUT ~0.36 s and GET ~0.21 s.

A 64 MB file over 40 ms with 1 MiB batches
(`node tests/bench-net.mjs 40 64 256 1024 48 32`) runs PUT ~1.64 s (~39 MB/s) and GET
~0.80 s (~80 MB/s). Across six runs PUT stayed within 1.62–1.66 s and GET within
0.79–0.85 s.

Node 22 runs these 2–4% faster. Node 20 can't run the bench: it has no
`Promise.withResolvers`.

### Live WAN

Two remote holders, RS(1,1), 256 KiB blocks, 512 KiB batches, 8 connections per
holder (the most a holder admits from one address), a 24 MB streaming window, 50 MB
per run:

| | rate | |
|---|---:|---|
| **PUT** | ~12.0 MB/s wire | ~6.0 MB/s of file, because RS(1,1) ships 2× |
| **GET** | ~19.3 MB/s | reads alternate between the two holders, which measured ~8% over reading every block from one |

Reproduce it against live nodes with:

```sh
node --experimental-websocket scripts/p2p-cli.mjs --peers … --size 50 \
     --timeout 30000 --guest-deadline 60000
```

Most of the gap between the two rows is the link, not the engine. Raw TCP over the
same path with the same 16 flows (`iperf3 -c <host> -P 16 -t 10`, and `-R` for the
download direction) carried ~14 MB/s up and ~29 MB/s down. So PUT runs at roughly
85–90% of what the uplink carries, and GET at about two thirds of the downlink. The
uplink is half the downlink, and RS(1,1) ships 2×, which is why PUT moves about a
third of the file bytes GET does. The iperf runs were not taken alongside the table,
and one of the three rounds ran at half those rates in both directions, so read the
percentages as approximate.

A real browser↔browser WebRTC link in the `p2p.html` demo reports ~13 MB/s in both
directions.

### QUIC and TCP on one pair

The same geometry (RS(1,1), 256 KiB blocks, 512 KiB batches, a 24 MB window, 50 MB per
run) on a second WAN pair: a Node initiator, one remote holder and one local holder,
both native `seedkernel` listening on TCP and QUIC. Both arms dial the holders directly,
with no relay. Timing starts only once every link is up. Three runs per arm, alternating
arms, each a PUT and two GETs:

| | PUT (wire) | GET |
|---|---:|---:|
| **QUIC**, 4 connections per holder | 14.1–16.0 MB/s | 28–42 MB/s |
| **QUIC**, 1 connection per holder | 15.5–16.6 MB/s | 35–41 MB/s |
| **TCP**, 8 connections per holder | 13.9–15.5 MB/s | 15–36 MB/s |

The uplink capped every arm's PUT at about the same rate, so the arms differ only in
GET, where QUIC is ahead: one TCP round read 15–25 MB/s, and without it TCP measured
32–36. With the uplink the limit, four QUIC connections did no better than one, so one is
p2p-cli's default for `quic://` peers. The QUIC connection (ngtcp2) runs under BBR. One
flow stands where TCP opens eight, and at each loss one CUBIC flow gives up 30% of its
rate where eight give up ~4% together, so CUBIC (the QUIC default) measured PUT at 0.74x
TCP on the same pair. Only half of each PUT crosses the WAN, since the other holder is
local, so these rates compare with each other and not with the table above. The local
holder needs a `quota` in its local config: without one it stores nothing, every GET
goes to the remote holder, and GET halves.

With both holders on the initiator's machine, over loopback (same geometry, a native
initiator, fresh holders for every run, three rounds alternating arms), the order flips.
Linux is WSL2 on the same laptop:

| | Windows PUT (wire) | Windows GET | Linux PUT (wire) | Linux GET |
|---|---:|---:|---:|---:|
| **QUIC**, 4 connections per holder | 51.7–60.4 MB/s | 65–96 MB/s | 61.9–63.8 MB/s | 67–93 MB/s |
| **TCP**, 8 connections per holder | 64.0–78.3 MB/s | 90–113 MB/s | 68.9–75.8 MB/s | 72–114 MB/s |

With no link to wait on, CPU is the limit. TCP hands the OS whole records and leaves
segmentation, acks and loss recovery to it. QUIC does that work in ngtcp2 in wasm and
seals and masks every ~1.4 KB packet. The transport's JS runs once per batch of packets,
not per packet. Besides ngtcp2, the per-packet cost is the socket call, so the native
loader sends a run of equal packets to one address in one call, cut below the socket
(UDP GSO on Linux, USO on Windows), and on Linux reads a run back in one call too (GRO).
On Windows that took QUIC PUT from 42–48 MB/s to the 52–60 above. On Linux it took a
run from ~340,000 socket calls to ~45,000 and the three nodes' CPU down ~12%, which
leaves QUIC at ~1.2x the CPU of TCP for the same transfer. Over a 20 ms, 250 Mbit link
between two Linux network namespaces, where the link sets the rate, it cut the nodes'
CPU by ~40% at the same rate. QUIC reaches ~0.8–0.9x TCP on PUT and ~0.8x on GET. One QUIC
connection or eight measure the same here. A holder closes a vanished client's QUIC
connections once the client is back and its new links name another process, so a bench
can restart its client at once. Until then they count against the holder's 8 per
source, so the old connections and the new must fit under it together.

**On Node, the main thread is the limit of a QUIC link.** With `p2p-cli.mjs` on Node as
the initiator against the same native holders (Windows), QUIC measured PUT 40.1–44.8
MB/s and GET 55–64, and TCP PUT 69.9–71.4 and GET 104–125. A CPU profile of the QUIC run
has the main thread ~87% busy: ~29% in `node:dgram`, most of it one send call per
~1.4 KB packet at ~8 µs each, ~26% in the transport's QuickJS realm, and ~5% in
`node:crypto`. Node has no batched or segmented send, so every packet pays that call.
The QUIC module's worker spends about a third of its time in `node:crypto`, but it waits
on the main thread for ~40%, so its crypto is off the critical path: keeping its
header-protection cipher between packets changed nothing in rate. TCP hands the OS whole
records and pays none of this.

`scripts/bench-native/run.sh` runs the native rows: it starts two native holders and a
native initiator, fresh for every run, and drives the initiator's streamed PUT and GET
over its control socket with the small Go program beside it (`go build` in `ctl/`, once).
With `WAN_TCP` or `WAN_QUIC` naming a remote holder it runs the WAN pair the same way.

```sh
SEEDKERNEL=../../seedkernel/native/seedkernel.exe bash scripts/bench-native/run.sh
```

For the Node rows, each holder listens on both
(`--listen <port>,quic=udp://0.0.0.0:<port>`; a QUIC listener binds every address) and
prints its key and `contact` secret. `p2p-cli.mjs` runs either arm:

```sh
# QUIC: each holder's quic listener, by IP address, one connection each
node scripts/p2p-cli.mjs --peers "<pkA>.<contactA>@quic://<ipA>:<port>,<pkB>.<contactB>@quic://<ipB>:<port>" \
     --size 50 --gets 2 --timeout 30000 --guest-deadline 60000
# TCP: each holder's tcp listener
node scripts/p2p-cli.mjs --peers "<pkA>.<contactA>@tcp://<hostA>:<port>,<pkB>.<contactB>@tcp://<hostB>:<port>" \
     --size 50 --gets 2 --timeout 30000 --guest-deadline 60000
```

### The two benches answer different questions

`bench-net.mjs` models a fixed per-message delay with no bandwidth limit and no
loss. Every message costs one RTT and a round of *W* messages lands together, so it
can't show refill or straggler effects. It does show guest CPU nearly at full value:
the `toHex` work alone moved its PUT by 7% and its GET by 10%, which the live link
doesn't show. Use `bench-net` to price guest CPU, and judge wire behaviour on a live
cohort.

## How the transfer engine is tuned

**Per-lane refill.** The window's *width* is not the lever. The host-call ledger
paces it to the realm's budget either way. What matters is how slots **refill**.
Lock-step rounds let one slow holder idle every other slot in the round. Giving each
slot its own lane over a shared cursor (`runStoreBatches`) measured **+22%** on the
same holders (paired and order-interleaved runs), and it removed a slow tail that
was making whole PUTs miss their deadline.

FETCH refills the same way: each reply is verified as soon as it lands, and its lane
takes the next request without waiting for the rest of the window.

**Pipelined windows.** A streamed PUT keeps one window placing while the next one
encodes and sends its OFFERs, and the index places alongside the file's last window. A
streamed GET fetches the next window while the current one is decrypted and handed back.
Without this, the wire would sit idle at every window boundary. Over a 40 ms link (16
MB, RS(2,2), 32 KiB blocks, 4 MiB windows;
`node tests/bench-net.mjs 40 16 32 256 48 32 4`), PUT takes ~1.11 s and GET ~0.64 s.

**One host-call ledger.** The two windows in flight share the realm's host-call
budget through one ledger (`hostBudget`), and every initiator call is charged against
it. The ledger has two FIFO classes. Foreground calls (crypto, codec, OFFER, HAVE)
are admitted before bulk calls (STORE, FETCH), and bulk always leaves room for the
largest call, so the next window's encode never waits behind the last window's
STOREs. Holder work stays off the ledger, so two nodes storing to each other can't
deadlock. A frame is built only once the ledger admits its call, so a lane waiting
its turn holds no copy of its blocks.

**Holder admission.** A holder admits only so many request bytes from one source at
once and answers the rest empty. The ledger alone doesn't prevent over-sending to one
holder: at defaults it lets out ~15 MiB while a holder admits ~10 MiB. So STORE lanes
start round-robin across peers, and a lane whose request comes back empty hands it to
that peer's other lanes and retires. Before this, most local 50 MB PUTs to two
holders failed with "no holder returned a verdict".

**Memory.** Two windows in flight cost memory, so the default window is a sixth of
`realmMemoryBytes`. A 64 MiB realm peaks at ~56 MiB during a PUT on a slow link.

## The guest deadline

seedkernel gives each guest invocation `DEFAULT_GUEST_DEADLINE_MS` (5 s). The budget
covers guest execution *and* the wall-clock time of every handoff. A window's calls
run under the invocation that fed that window, so its encode and placement must
finish within the deadline, even though placement completes during the next feed.
Running over fails the whole PUT with
`guest: handoff deadline exhausted before host.call`.

This is not the request timeout. Raise `guestDeadlineMs` (`--guest-deadline` in
p2p-cli), not `--timeout`. Nothing derives the window size from the deadline
(`windowTargetBytes` comes from `realmMemoryBytes`), so a wider window or a slower
link needs a higher deadline to match. Also raise it before any throughput A/B test.
Otherwise the deadline kills the slow runs, and the arm that loses its slow runs
looks faster.

## Holder ingest

`node tests/bench-holder.mjs 16 256 1 1 disk` isolates holder admission and durable
STORE work on a real filesystem. Each holder runs in a process of its own, on Node's own
AES and SHA-256 and reached over loopback TCP through the real transport, as a deployed
holder is. The median of six runs on Node 24: ~4.2 ms per 256 KiB block, a ~60 MB/s mean
holder rate, and PUT ~0.38 s (~42 MB/s). About 2 ms of that block time is waiting, not
work: each STORE batch awaits a score from the reputation module's worker before it
admits, and the timer in `handle` runs through the wait. Without that await a block
measures ~3.0 ms (~85 MB/s) and PUT stays the same, so the mean holder rate understates
what a holder can take. The crypto floor is ~0.26 ms per block; the rest is the fs
write, seam crossings and QuickJS. With the in-RAM fs (leave off `disk`) a block takes
~2.1 ms, so the disk is ~2.1 ms of it. The capacity comparison uses total holder payload
over the complete PUT wall time as a conservative floor (~86 MB/s, 12× the live run's
demand). It separately sums the holders' measured rates for the active holder window
(~121 MB/s). Node 22 is within 3%.
