# seedstore: WASM implementation

This is an AssemblyScript + TypeScript implementation of **Part I** of the
[seedstore spec](../docs/SPEC.md), a private, self-healing peer-to-peer storage
layer that runs on [seedkernel](https://github.com/arj03/seedkernel). A node runs the
same protocol in Node, the browser and seedkernel's native binary. Spec references in
this file and in code comments (`§n`, `SPEC §n`) point to that spec.

## Seedstore is content, not a binary

The deployable artifact is the **generic seedkernel host**, which knows nothing
about storage. Seedstore ships as **signed content**. The host loads that content
and becomes a storage node:

```
seedstore.skb: one signed bundle, verified at load
  codec.wasm, reputation.wasm   Reed–Solomon + reciprocity math; pure, no grants
  guest.js                      the whole protocol, in a zero-authority JS realm:
                                PUT/GET/repair (initiator) + HAVE/OFFER/STORE/FETCH (holder)
        │ reaches I/O only through host.call(name, bytes)
        ▼
seedkernel host                 install + admission policy, and the services:
                                node (scoped sign/verify), fs, _net (transport), crypto/*
```

Everything with *structure* belongs to seedstore and lives in the bundle: content
addressing, the signed chunk descriptor, the wire format, Reed–Solomon, the nonce
convention and the quota. The host only moves opaque bytes. So the same host can run
storage or any other signed app, and an upgrade to storage is new content rather than
a new binary (§2.1, §17). The runtime side (the host, the guest seam and its grants,
the confinement realm, the bundle format) is documented in
[seedkernel RUNTIME §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)
and [CLIENT](https://github.com/arj03/seedkernel/blob/main/docs/CLIENT.md).

## Build

seedkernel is a **path dependency** on a sibling checkout (`../../seedkernel`).
Build it first:

```sh
(cd ../../seedkernel/WASM && npm install && npm run build)
```

Then, from this directory:

```sh
npm install
npm run build      # codec + reputation WASM, host TS, the guest, minified host, signed bundle
npm test           # build, then run the full suite on Node
```

`npm run build` produces:
- `build/codec.wasm` and `build/reputation.wasm`
- the compiled host in `build/host/`, plus a comment-stripped copy in `build/host-min/`
- the assembled guest, `build/host/tier2-guest.js`
- the signed bundle, `bundle/seedstore.skb`

The first build mints the bundle author key, `seedstore-author.key`. Keep it secret.
Beside it, `seedstore-author.version` tracks the bundle's monotonic version, and
hosts refuse downgrades. Both files are gitignored, and they must travel together.

## Run a node from the command line

A node is the seedkernel host plus two signed bundles: seedkernel's **transport
bundle**, which is the node's network and is installed at boot, and the seedstore
bundle. The host admits apps only from authors named in its policy file. Put the
author public key printed by `npm run build:bundle` in one:

```sh
echo '{ "authors": ["<author-pubkey-hex>"] }' > allowed-keys.json
```

Start a few holders. Each one prints its `<peer-pubkey>`:

```sh
SHELL=../../seedkernel/WASM/build/host/loader-node.js

node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb \
     --dir ./data-A --key ./A.key --listen 127.0.0.1:7401
#   bundle seedstore v1  author <author-pubkey-hex>  serves seedstore
#   serving the app's request side from the confined guest
#   tcp    listening on :7401
```

Then PUT and GET from a client that lists the holders as `--peers`
(`<pubkey>@host:port`, comma-separated):

```sh
PEERS="<pkA>@127.0.0.1:7401,<pkB>@127.0.0.1:7402,<pkC>@127.0.0.1:7403,<pkD>@127.0.0.1:7404"

node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb --dir ./client \
     --peers "$PEERS" --op put < ./notes.txt > ./receipt.bin

# A GET takes K ‖ root, cut out of the PUT receipt:
#   [K 32][chunkCount u32][placed u32][intended u32][rootLen u32][root …][idCount u32][ids …]
node -e 'const b=require("fs").readFileSync("receipt.bin"), n=b.readUInt32BE(44);
process.stdout.write(Buffer.concat([b.subarray(0,32), b.subarray(48,48+n)]))' > getarg.bin

node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb --dir ./client \
     --peers "$PEERS" --op get < ./getarg.bin > ./restored.txt
```

`--op` is the host's only app-facing flag (seedkernel §12.8). It passes stdin to the
named op on the app's `handle` and writes the answer to stdout. Operator logging goes
to stderr, so the redirects carry only app bytes. The root is a signed descriptor of
variable length (§4.3), which is why the GET argument reads its length from the
receipt. Keep `K`: without it, the holders hold permanent noise (§11).

Every other flag belongs to the host: `--listen`/`--peers`/`--dir`/
`--key`/`--guest-timeout`/`--guest-memory`, and more. A node with no listener is a
pure client, and a node with a listener serves until Ctrl-C. seedkernel's native
single-file `seedkernel` binary loads the same bundle (seedkernel §12.9).

To benchmark PUT/GET against live nodes listening with `--listen ws=…`, see `scripts/p2p-cli.mjs`
and [PERFORMANCE.md](../docs/PERFORMANCE.md).

## Use it as a library

For tests and embedding, you can drive nodes over an in-process network:

```js
import { createConnectedCohort, loadSodium, loadWasmBytes, LoopbackNetwork } from "./build/host/node.js";

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
const net = new LoopbackNetwork();
const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: { k: 2, m: 2, blockSize: 512 } });

const data = new TextEncoder().encode("hello, cohort");
const put = await nodes[0].put(data);              // chunk → encrypt → RS → place → root
const got = await nodes[0].get(put.root, put.key); // locate → fetch any k → decode → decrypt
```

`LoopbackNetwork` runs the real transport bundle (AKE, record layer, routing) over
in-memory channel pairs, so an in-process cohort exercises the shipped stack. There
is one protocol implementation. Each node is one the seedkernel host stands up, with
the signed transport installed (`storageRuntime` over a host's `standUp`: an in-memory
host of its own per node here, `bootNodeShell` on a server, the page's `browserHost` in a
browser). `StorageNode` installs the signed storage bundle on it and drives the confined
guest, and nothing else. The block store is the host's: in memory here, a directory on a
server, OPFS/IndexedDB in a browser (§12).

## Browser demos

```sh
npm run serve:demo      # builds build/browser-demo, serves it on :3000
#   http://localhost:3000/index.html   in-tab cohort
#   http://localhost:3000/p2p.html     a real node against real holders
```

**`index.html`** boots a cohort inside one tab. It stores a file across the cohort,
reads it back, and lets you take peers offline and watch repair restore redundancy.

**`p2p.html`** makes the tab a full storage node. A dropped file is encrypted and
replicated (RS(1,1)) across the other nodes, and any node can rebuild it from the
retrieval token. You pick one of two transports on the page:

- **Direct WebSocket** (the default) dials holders at a `ws`-labelled listener, with
  no relay or STUN. Start holders with `--listen ws=0.0.0.0:47210 …` and paste each
  one's `pubkey[.secret]@host:port` into the peers box.
- **WebRTC** finds peers in a room on a relay
  ([seedrelay](https://github.com/arj03/seedrelay)), links to them through it, and
  then moves to a direct connection, using STUN for NAT traversal; where that fails,
  the link stays on the relay. Use it when holders have no port you could paste. The
  page meets the room with seedrelay's room client and registers on the relay
  (`netRelay`); the transport bundle links to each member and negotiates every peer
  connection over sockets the page supplies (seedkernel §12.7). For the cohort,
  open 3+ tabs in one room, or one tab plus console holders:

  ```sh
  (cd ../../seedshell && npm run relay)  # seedrelay on ws://localhost:8080
  npm run serve:holder                   # a console holder joining the room; run two
  #   then pick WebRTC in p2p.html (relay ws://localhost:8080, room "seedstore-demo")
  ```

  Console holders have no WebRTC, so a tab's link to one stays on the relay. Between
  themselves they move to a UDP path (the transport's, seedkernel §12.7). `npm run
  smoke:relay` runs the PUT→GET path headless, with no browser, through the relay and
  then over UDP, against the sibling seedrelay checkout's server, which it starts on a free port as a private
  relay with a fresh secret; `RELAY=ws://host:port` points it at a running one.

  A private relay (seedrelay's `--secret`) serves only nodes that prove its secret.
  Give it to the page's **relay secret** box, or to a console holder or the smoke as
  `RELAY_SECRET`; `netRelay` passes it to the transport, and the room client proves
  it with libsodium's BLAKE2b. It never crosses the wire, but whoever sees a
  registration can test guesses at it, so it must be long and random.

A tab's block store is in RAM, because the OPFS/IndexedDB backend isn't built yet.
Tabs acting as holders therefore forget everything on reload. For now, treat the
browser as the file's **owner**, and let `seedkernel` or console holders keep the
bytes.

## Code map

| Component | Where | Spec |
| --- | --- | --- |
| GF(2⁸) + systematic Reed–Solomon encode/decode | `assembly/codec/`, which is WASM with no grants, called as `host.call("codec", …)` | §4.1, §9 |
| Decayed per-peer reciprocity counters | `assembly/reputation/`, which is WASM with no grants | §13 |
| The whole protocol: PUT/GET, the index tree, placement, have/want, repair, and the holder side (admission, sibling rule, quota, allowance, tiers, eviction, store writes) | `host/tier2-guest.orchestration.js`, assembled with the shared cores into `build/host/tier2-guest.js` by `scripts/build-guest.mjs` | §5–§10, §14 |
| Wire format for HAVE/OFFER/STORE/FETCH | `host/protocol.ts` (shared with the guest) | §18 |
| Descriptor layout, tags, copy targets, loss margin | `host/descriptor-core.ts` (shared with the guest) | §4.1, §4.3, §8 |
| Scoped descriptor sign/verify, host side | `host/descriptor.ts` | §16 |
| Stand a node up on a seedkernel host | `host/runtime.ts`, with entries `host/node.ts` and `host/browser.ts` | §19 |
| Install the bundle on that node and drive the guest | `host/storage-node.ts` | §19 |
| Bundle manifest and signing | `scripts/storage-bundle.mjs`, `scripts/build-bundle.mjs` | §2, §17 |

The guest is assembled from `util`, `reputation-core`, `protocol` and
`descriptor-core`, and the host imports the same files. So the wire format and the
descriptor have **one** definition, not a hand-copied second one.

**Crypto is reused, not bundled.** The guest calls the host's ungated
`crypto/blake2b` and `crypto/chacha20poly1305-ietf/{seal,open}` transforms. It
keeps ciphertext length-preserving for RS and carries each detached 16-byte tag
inside the signed descriptor. A block id includes the descriptor's author in the hash
(§4.2):
`BLAKE2b-256("seedstore:block\0" ‖ authorPk[32] ‖ ciphertext)`. Key-sealing lives
host-side in `host/crypto.ts`.

**Signatures are scoped.** The guest signs with `node/sign` and verifies with
`node/verify`, which the host scopes to the bundle's `app` label (seedkernel §12.2), and
the host-side mirror in `descriptor.ts` uses the same two names. Each signed format opens with its own tag: `TAG_DESCRIPTOR = 0x01`, with
`0x02` (tombstone) and `0x03` (head) reserved for Part II.

**The holder's store.** On first access the guest rebuilds its index of held ids and
quota usage from `FS_LIST`/`FS_SIZE`. After that it updates the index on each STORE,
so sibling checks don't need filesystem calls. A block commits as one
`<block-id>.rec` file (`[descriptor length][descriptor][ciphertext]`), with a
`<block-id>.tag` beside it (`[tier][author]`) that records its §14 tier and the author
its bytes count against. The tag is written first, so a record without one never
committed and is not held.

**Tiers and eviction (§14).** Every accepted block starts committed. A repair audit
that finds a block above its target moves the surplus copies to cache: every holder
sorts the block's live holders the same way, and the ones past the target step down.
A later audit that finds the chunk short again moves them back. A STORE needs room
only beside the committed tier, and evicts cache, coldest first, for any shortfall.
When the store is over quota (the operator lowered it), the repair pass drops cache
first. It then releases commitments, lowest-standing author first. Each one is
re-placed on another peer first, or kept if the chunk would drop below low water
without it.

**Admission weighs standing (§13.2).** An author placing its own chunks may fill
`newcomerShare` (default 0.5) of a holder's quota while the holder has no record of
it, all of it with positive standing, and none with negative standing. The holder
answers `allowance` past that. A repairer re-placing another author's chunk is not
charged to anyone's allowance, so repair outranks routine placement. Set
`newcomerShare: 1` to turn this off, for example among one person's own devices.

**Sampled verification (§8).** A repair audit fetches one block from each advertising
holder that has no verification pass in the last `verifyFreshMs` (default 15 min),
plus 2 of the rest, least recently verified first. Each is a one-block FETCH, and a
correct answer slower than `verifyDeadlineMs` (default 2 s) fails. A holder counts as
live for every block it advertises while its last pass is fresh, so a pass costs
about 2 fetches per chunk once the cohort is verified. Heal then fetches only the
blocks it copies or decodes from.

**One realm.** The initiator and holder sides share one confined realm and its one
`handle` entrypoint, which runs one invocation at a time (seedkernel §12.3). So when an
initiator is parked on an `await`, an inbound request queues behind it. That costs latency on a busy node, but it never
affects correctness.

## Tests

`npm test` builds everything and then runs `tests/run.mjs`:

| Suite | Covers |
| --- | --- |
| `codec` | any-*k*-of-*n* recovery across every loss pattern, deterministic encode, systematic pass-through, block-id ≡ libsodium, byte-identical re-encode |
| `bridges` | the host crypto primitives |
| `descriptor` | descriptor round trips, tamper evidence under the scoped signature, index-list encryption, multiplicity as the replica count, loss margin |
| `protocol` | batched OFFER/STORE/FETCH encoding; batch-wide sibling, quota and newcomer-allowance rules; a STORE evicts cache, never a commitment; a missing, forged, foreign or mismatched descriptor is declined; concurrent STOREs can't race a sibling reservation |
| `reputation` | passes raise the score, misses penalize it, scores decay |
| `storage` | multi-node PUT→GET, small-file replication, offline tolerance, repair (including mixed geometry), sampled audits, a holder advertising what it cannot serve, cache demotion and re-promotion, graceful release over quota, key sharing, crypto-shredding, reciprocity |
| `security` | a peer can't claim another author's block ids, roots are authenticated before use, malformed holder responses can't abort GET or repair, a late verification answer is not live, FETCH reply bounds |
| `concurrency` | round-trip economy over a latency-bearing link, asserted as request counts |
| `net` | the store persisting across a cold reopen, a cohort over real TCP, a browser-like node over real WebSocket |
| `browser` | a node booted through the `fetch`-based browser entry |
| `shell-run` | a generic seedkernel shell loads the signed bundle and runs PUT/GET; a bundle downgrade is refused |
| `holder-guest` | a cohort of generic shells with confined holders; concurrent initiators on one realm |

The benches (`tests/bench.mjs`, `bench-net.mjs`, `bench-holder.mjs`) are not part of
`npm test`. For those, see [PERFORMANCE.md](../docs/PERFORMANCE.md).

## Performance

In brief: the codec writes ~194 MB/s and reads ~2.7 GB/s on one core, so the network
sets end-to-end speed. A live WAN run with two holders measured ~12.0 MB/s PUT on the
wire and ~19.3 MB/s GET, where raw TCP on the same link carries ~14 MB/s up and
~29 MB/s down. [PERFORMANCE.md](../docs/PERFORMANCE.md) has the tables, the commands
to reproduce them, and the transfer-engine tuning notes: per-lane refill, pipelined
windows, the host-call ledger, and the guest deadline.

## Footprint

| Artifact | Size |
| --- | ---: |
| `codec.wasm`, including SIMD RS and GF tables | 8.7 KB |
| `reputation.wasm` | 5.3 KB |
| the guest, minified | 75 KB (20 KB gzipped) |

Those three files are all of seedstore's runtime code. Everything else is the
seedkernel host and its core libsodium, which any app on that host shares.

The host-side TypeScript in `build/host` (minified to `build/host-min`) is a separate
path. It is the in-process library that the browser demo and the tests load in place
of a stand-alone host. `scripts/minify.mjs` is a small, dependency-free comment
stripper, not a bundler. It checks every file it emits with `node --check`.

## Layout

```
assembly/codec/        gf256.ts, rs.ts, index.ts       Reed–Solomon WASM module
assembly/reputation/   index.ts                        reciprocity WASM module
host/  tier2-guest.orchestration.js   the confined guest: the whole protocol
       protocol / descriptor-core / reputation-core / util   pure cores shared with the guest
       runtime.ts                     stands a node up on a seedkernel host
       storage-node.ts                installs the bundle on it, drives the guest
       crypto / descriptor / sodium / store-view / core      host-side helpers
       node.ts / browser.ts / cluster.ts / loopback.ts       entry points, test cohorts
browser/   index.html, p2p.html                        demos
scripts/   build-guest / build-bundle / storage-bundle build steps
           build-browser-demo / minify / clean
           p2p-cli                                     headless PUT/GET against live nodes
           serve-holder / smoke-relay / relay-room     console holders in a relay room
tests/     *.test.mjs (run.mjs), bench*.mjs, harness + helpers + fixtures
```

## Where the implementation departs from the spec

Part II (§20–§27) is out of scope. Within Part I, the implementation takes a simpler
form in some places and leaves other parts of the spec unbuilt.

### Simpler reference forms

- **Liveness (§8).** There is no Suspected state and no grace window. A holder is
  either verified-live or not, and repair heals on the first miss. This is safe
  because repair is idempotent. It just does more repair work under churn.
- **The bulk plane (§3).** Blocks ride ordinary request/response bodies inside the
  encrypted record layer, which is what the seedkernel transport provides. There is
  no separate bulk frame stream.
- **Best-effort PUT.** A PUT spreads each chunk across as many distinct holders as the
  cohort offers, and it succeeds once *k* distinct blocks land. On a thin cohort,
  redundancy starts below target and repair tops it up as holders appear. That is
  what lets the demos store across one or two holders. A deployment that must
  guarantee full durability at write time would fail the PUT instead.
- **The browser demos use *k* = 1**, meaning replication, because surviving the loss
  of one holder in a two- or three-node cohort can't be done with coding.

### Not yet built

- **A read cache (§14).** The cache tier holds only surplus copies that repair
  stepped down. A node does not keep blocks it fetched while reading.
- **Reclaiming removed files (§11).** Removal is crypto-shredding only, and the
  shredded blocks are never reclaimed. Eviction drops cache and, over quota, the
  lowest-standing commitments, but nothing ages out a long-unread committed block.
  Because every holder repairs every chunk it holds, repair keeps shredded chunks
  at full redundancy indefinitely.
- **The rest of admission (§14).** Admission weighs the author's standing, but not
  social closeness, since nodes carry no cluster tag. A holder does not measure how
  under-replicated an offered chunk is either. It treats any placement by someone
  other than the author as repair, so an author with a friend to place for it gets
  past its allowance.
- **The full reciprocity score (§13.1).** The score counts passes and misses on the
  fetches that GET and repair audits already make, with a 7-day half-life. It is not
  netted against how much a node stores for that peer. There is no separate
  spot-check schedule, so an owner that holds no block of its own file never
  audits that file.
- **Placement beyond standing (§6, §8).** Placement ranks peers by reciprocity score
  alone. It does not spread a chunk across social clusters or prefer long-lived
  peers over browser tabs, since nodes carry no cluster or longevity tag.
- **Proactive re-spreading (§9).** Repair runs only when a chunk drops below its
  low-water mark. Nothing moves blocks toward healthier peers ahead of time when the
  cohort thins.
- **Browser storage (§12).** A tab's block store is in RAM, because the
  OPFS/IndexedDB backend isn't built yet, so a tab that acts as a holder forgets
  everything on reload (see [Browser demos](#browser-demos)).
