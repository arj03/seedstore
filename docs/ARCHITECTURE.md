# seedstore: architecture

How the implementation in [`WASM/`](../WASM/) is put together: what ships, where each
part of the protocol lives, how a holder keeps its store, and where the code departs from
the [spec](SPEC.md). The [README](../README.md) says how to run it. Spec references here and
in code comments (`§n`, `SPEC §n`) point to the spec.

## Content, not a binary

The deployable artifact is the **generic seedkernel host**, which knows nothing about
storage. Seedstore ships as **signed content**. The host loads that content and becomes a
storage node:

```
seedstore.skb: one signed bundle, verified at load
  codec.wasm, reputation.wasm   Reed–Solomon + reciprocity math; pure, no grants
  guest.js                      the whole protocol, in a zero-authority JS realm:
                                PUT/GET/repair (initiator) + HAVE/OFFER/STORE/FETCH/REPAIR (holder)
        │ reaches I/O only through host.call(name, bytes)
        ▼
seedkernel host                 install + admission policy, and the services:
                                node (scoped sign/verify), fs, _net (transport), crypto/*
```

Everything with *structure* belongs to seedstore and lives in the bundle: content
addressing, the signed chunk descriptor, the wire format, Reed–Solomon, the nonce
convention and the quota. The host only moves opaque bytes. So the same host can run
storage or any other signed app, and an upgrade to storage is new content rather than a
new binary (§2.1, §17). The runtime side (the host, the guest seam and its grants, the
confinement realm, the bundle format) is documented in
[seedkernel ARCHITECTURE §12](https://github.com/arj03/seedkernel/blob/main/docs/ARCHITECTURE.md)
and [CLIENT](https://github.com/arj03/seedkernel/blob/main/docs/CLIENT.md).

## Code map

| Component | Where | Spec |
| --- | --- | --- |
| GF(2⁸) + systematic Reed–Solomon encode/decode | `assembly/codec/`, which is WASM with no grants, called as `host.call("codec", …)` | §4.1, §9 |
| Decayed per-peer reciprocity counters | `assembly/reputation/`, which is WASM with no grants | §13 |
| The whole protocol: PUT/GET, the index tree, placement, have/want, repair (auditing, asking, and rebuilding what this node agreed to), and the holder side (the roster, admission, sibling rule, quota, allowance, tiers, eviction, store writes) | `host/tier2-guest.orchestration.js`, assembled with the shared cores into `build/host/tier2-guest.js` by `scripts/build-guest.mjs` | §5–§10, §14 |
| Wire format for HAVE/OFFER/STORE/FETCH | `host/protocol.ts` (shared with the guest) | §18 |
| Descriptor layout, tags, copy targets, loss margin | `host/descriptor-core.ts` (shared with the guest) | §4.1, §4.3, §8 |
| The holder's record, tag and saved index | `host/store-record.ts` (shared with the guest) | §12 |
| Scoped descriptor sign/verify, host side | `host/descriptor.ts` | §16 |
| Stand a node up on a seedkernel host | `host/runtime.ts`, with entries `host/node.ts` and `host/browser.ts` | §19 |
| Install the bundle on that node and drive the guest | `host/storage-node.ts` | §19 |
| The client ops over any invoke, and the file token | `host/client.ts` | §18.1 |
| Bundle manifest and signing | `scripts/storage-bundle.mjs`, `scripts/build-bundle.mjs` | §2, §17 |

The guest is assembled from `util`, `reputation-core`, `protocol`, `descriptor-core` and
`store-record`, and the host imports the same files. So the wire format, the descriptor
and the store layout have **one** definition, not a hand-copied second one.

**Crypto is reused, not bundled.** The guest calls the host's ungated `crypto/sha256` and
`crypto/aes256gcm/{seal,open}` transforms. It keeps ciphertext length-preserving for RS
and carries each detached 16-byte tag inside the signed descriptor. A block id includes
the descriptor's author in the hash (§4.2):
`SHA-256("seedstore:block\0" ‖ authorPk[32] ‖ ciphertext)`. Key-sealing lives host-side
in `host/crypto.ts`.

**Signatures are scoped.** The guest signs with `identity/sign` and verifies with
`identity/verify`, which the host scopes to the bundle's `app` label (seedkernel §12.2), and
the host-side mirror in `descriptor.ts` uses the same two names. Each signed format opens
with its own tag: `TAG_DESCRIPTOR = 0x01`, with `0x02` (tombstone) and `0x03` (head)
reserved for Part II. A holder sees each descriptor at OFFER and again at STORE, so it
keeps the envelopes that verified and checks a STORE's against them byte for byte instead
of verifying twice.

## The holder

**The store.** A block commits as one `<block-id>.rec` file (`[descriptor
length][descriptor][ciphertext]`), written atomically, so a record on disk is held. It
counts against the author and group its descriptor names. A block that changes §14 tier
also gets a `<block-id>.tag` (`[tier][author][group]`), so the common write stays one
file. The guest keeps an index of held ids and quota usage, so sibling checks need no
filesystem calls, and saves it as `store.idx` once an eighth of it is new. A restart
reads that file and only the records written since, not every block. The listing still
decides what is held: a row whose record is gone is ignored. A store with no index yet is
read a few records at a time and saved as it goes, so a store too large to read inside
one guest deadline is read over the first few requests.

**Tiers and eviction (§14).** Every accepted block starts committed. A repair audit that
finds a block above its target moves the surplus copies to cache: every holder sorts the
block's live holders the same way, and the ones past the target step down. A later audit
that finds the chunk short again moves them back. A STORE needs room only beside the
committed tier, and evicts cache, coldest first, for any shortfall. When the store is over
quota (the operator lowered it), the repair pass drops cache first. It then releases
commitments, lowest-standing author first. A copy goes once the chunk stays at or above
low water without it; until then the pass asks another member to repair the copy it would
leave missing, and drops its own on a later pass.

**Repair is pulled (§9).** Holders audit their chunks, and for each copy a short chunk
lacks they send a group member that holds none of it a REPAIR request: the signed
descriptor, the block wanted, the chunk's dependable margin, and who holds which blocks.
The member decides under its own admission and answers. Yes is a promise: it fetches what
it needs, rebuilds the block, checks it against the signed id and stores it, on a timer
wake after it has answered, retrying a failed fetch with backoff for up to two minutes.
Its fetches are REPAIR_FETCH, which lead with the chunk's key, so every holder serving one
notes the chunk as being repaired and sends no request for it meanwhile, as does the
holder that asked. A holder takes that note only from a member of the chunk's group naming
a block of the chunk it holds, and only once per shortfall: two minutes after the first,
it asks for the repair itself whatever further REPAIR_FETCHes say, until an audit finds
the chunk healthy, so a member cannot hold a chunk's repair off by claiming it. The asker
sends its requests together, at the end of its pass, so the members answer before they
start fetching from it. A pass audits the held blocks for at most 1.5 s, resuming where
the last one stopped, so a large store is audited over several passes. STORE and OFFER
are accepted only from the chunk's author, so nobody pushes bytes onto a holder for
someone else.

**Groups (§5.1).** Each node keeps a roster of named groups, operator policy like the
quota: `groups` at boot, `setGroups` later. A node answers nothing to a peer outside it. A
PUT names one group and signs the name into every descriptor, its blocks go only to that
group's linked members, and a holder admits a block only if it lists both the author and
the sender under that name (`not-in-group` otherwise). Standing is kept per (group, peer):
a peer's service counts in the group of the chunk it served. The roster is dynamic:
`setGroups` (the guest's `groups` op) replaces it whole, and the next request reads the
new one, so a separate groups app can keep it.

## The ledger (§13)

Each node keeps, per (group, peer), three things it saw itself:

- **Reliability:** verified fetches passed against missed, with a 7-day half-life.
- **Availability:** repair passes the peer was linked at against passes it was not,
  decayed the same way. It measures uptime, so no longevity tag is needed.
- **Holdings:** bytes the peer verifiably holds for this node. A PUT saves its chunks'
  signed descriptors as `own.*` records (no content key), and each repair pass audits 32
  of them in turn, as it audits the chunks it holds.

The ledger is written to the store after every repair pass and read back before the
node's first request, so a restart keeps it: reliability, availability and the own-audit
cursor in a `ledger` record, and holdings per chunk in a `held.<part>` record beside each
`own.*` part.

Everything that weighs a peer reads that ledger:

- **Ranking.** Placement, repair targets and reads order peers by reliability ×
  availability, so a steady peer gets a copy before a browser tab that comes and goes.
- **Health.** A chunk counts only its copies on dependable holders, those linked at least
  half the time. A chunk sitting on often-offline peers is short, and repaired onto
  steadier ones, before it loses anything. When the flaky copies come back as surplus,
  they are the ones that step down to cache.
- **Urgency.** A REPAIR request carries the chunk's dependable margin, and a member runs
  its agreed repairs lowest margin first.
- **Allowance (§13.2).** An author's blocks in a group, pushed or repaired, may fill
  `newcomerShare` (default 0.5) of a holder's quota plus what the author verifiably holds
  for that holder there, up to the whole quota, and nothing while it fails more checks
  than it passes. The holder answers `allowance` past that. Set `newcomerShare: 1` to turn
  this off, for example among one person's own devices.

**Sampled verification (§8).** A repair audit fetches one block from each advertising
holder that has no verification pass in the last `verifyFreshMs` (default 15 min), plus 2
of the rest, least recently verified first. Each is a one-block FETCH, and a correct
answer slower than `verifyDeadlineMs` (default 30 s, a bound for a stuck holder rather
than a slow one) fails. A holder counts as live for every block it advertises while its
last pass is fresh, so a pass costs about 2 fetches per chunk once the cohort is verified.
Heal then fetches only the blocks it copies or decodes from.

**One realm.** The initiator and holder sides share one confined realm: the host drives
the initiator at `onHost`, and peers reach the holder at `onPeer`. The realm runs one
invocation at a time (seedkernel §12.3). So when an
initiator is parked on an `await`, an inbound request queues behind it. That costs latency
on a busy node, but it never affects correctness.

## Tests

`npm test` builds everything and then runs `tests/run.mjs`:

| Suite | Covers |
| --- | --- |
| `codec` | any-*k*-of-*n* recovery across every loss pattern, deterministic encode, systematic pass-through, block-id ≡ libsodium, byte-identical re-encode |
| `bridges` | the host crypto primitives |
| `descriptor` | descriptor round trips, tamper evidence under the scoped signature, index-list encryption, multiplicity as the replica count, loss margin |
| `protocol` | batched OFFER/STORE/FETCH encoding; batch-wide sibling, quota and newcomer-allowance rules; a STORE evicts cache, never a commitment; a missing, forged, foreign or mismatched descriptor is declined; concurrent STOREs can't race a sibling reservation |
| `reputation` | passes raise the score, misses penalize it, scores decay |
| `ledger` | a chunk counting only dependable copies, ranking by reliability × availability, repairs most urgent first, the allowance netted against what an author holds for the holder |
| `storage` | multi-node PUT→GET, small-file replication and short blocks, offline tolerance, repair (including mixed geometry), groups (strangers refused, placement inside a group, per-group standing), sampled audits, a holder advertising what it cannot serve, cache demotion and re-promotion, graceful release over quota, key sharing, crypto-shredding, reciprocity |
| `security` | a peer can't claim another author's block ids, roots are authenticated before use, a reused signature over a changed descriptor is refused, malformed holder responses can't abort GET or repair, a third party cannot push an author's block, a late verification answer is not live, FETCH reply bounds |
| `concurrency` | round-trip economy over a latency-bearing link, asserted as request counts |
| `net` | the store persisting across a cold reopen, a restart from the saved index, a cohort over real TCP, a browser-like node over real WebSocket |
| `browser` | a node booted through the `fetch`-based browser entry |
| `shell-run` | a generic seedkernel shell loads the signed bundle and runs PUT/GET; a bundle downgrade is refused |
| `holder-guest` | a cohort of generic shells with confined holders; concurrent initiators on one realm |

The benches (`tests/bench.mjs`, `bench-net.mjs`, `bench-holder.mjs`, `bench-boot.mjs`)
are not part of `npm test`. For those, see [PERFORMANCE.md](PERFORMANCE.md).

## Footprint

| Artifact | Size |
| --- | ---: |
| `codec.wasm`, including SIMD RS and GF tables | 8.7 KB |
| `reputation.wasm` | 5.3 KB |
| the guest, as the bundle signs it, without comments | 101 KB (27 KB gzipped) |

Those three files are all of seedstore's runtime code. Everything else is the seedkernel
host and its core libsodium, which any app on that host shares.

The host-side TypeScript in `build/host` (minified to `build/host-min`) is a separate path.
It is the in-process library that the browser demo and the tests load in place of a
stand-alone host. `scripts/minify.mjs` is a small, dependency-free comment stripper, not a
bundler. It checks every file it emits with `node --check`.

## Layout

```
WASM/
  assembly/codec/        gf256.ts, rs.ts, index.ts       Reed–Solomon WASM module
  assembly/reputation/   index.ts                        reciprocity WASM module
  host/  tier2-guest.orchestration.js   the confined guest: the whole protocol
         protocol / descriptor-core / store-record / reputation-core / util   pure cores shared with the guest
         runtime.ts                     stands a node up on a seedkernel host
         storage-node.ts                installs the bundle on it, drives the guest
         client.ts                      the client ops over any invoke, and the file token
         crypto / descriptor / sodium / store-view / core      host-side helpers
         node.ts / browser.ts / cluster.ts / loopback.ts       entry points, test cohorts
  browser/   index.html, p2p.html                        demos
  scripts/   build-guest / build-bundle / storage-bundle build steps
             build-browser-demo / minify / clean
             seedstore                                   put / get / ls / where / holdings / probe
             p2p-cli                                     the PUT/GET benchmark against live nodes
             bench-native/                               the PUT/GET benchmark with native nodes throughout
             boot-node                                   the one node assembly the scripts share
             serve-holder / smoke-relay / relay-room     console holders in a relay room
  tests/     *.test.mjs (run.mjs), bench*.mjs, harness + helpers + fixtures
```

## Where the implementation departs from the spec

Part II (§20–§27) is out of scope. Within Part I, the implementation takes a simpler form
in some places and leaves other parts of the spec unbuilt.

### Simpler reference forms

- **Liveness (§8).** There is no Suspected state and no grace window. A holder is either
  verified-live or not, and repair heals on the first miss. This is safe because repair is
  idempotent. It just does more repair work under churn.
- **The bulk plane (§3).** Blocks ride ordinary request/response bodies inside the
  encrypted record layer, which is what the seedkernel transport provides. There is no
  separate bulk frame stream.
- **Best-effort PUT.** A PUT spreads each chunk across as many distinct holders as the
  cohort offers, and it succeeds once *k* distinct blocks land. On a thin cohort,
  redundancy starts below target and repair tops it up as holders appear. That is what
  lets the demos store across one or two holders. A deployment that must guarantee full
  durability at write time would fail the PUT instead.
- **The browser demos use *k* = 1**, meaning replication, because surviving the loss of
  one holder in a two- or three-node cohort can't be done with coding.

### Not yet built

- **A read cache (§14).** The cache tier holds only surplus copies that repair stepped
  down. A node does not keep blocks it fetched while reading.
- **Reclaiming removed files (§11).** Removal is crypto-shredding only, and the shredded
  blocks are never reclaimed. Eviction drops cache and, over quota, the lowest-standing
  commitments, but nothing ages out a long-unread committed block. Because every holder
  repairs every chunk it holds, repair keeps shredded chunks at full redundancy
  indefinitely, and an owner's file list keeps every file it put.
- **Correlated failure (§6, §10).** Placement spreads a chunk over distinct, steady
  members, but it cannot tell which members fail together, such as two devices on one
  power strip, since nothing a node observes says so until it happens.
- **The ledger stays local.** Each device keeps its own: what a friend holds for my laptop
  raises its allowance at my laptop, not at my phone. Agreed repairs and verification
  passes live in memory, so a restart drops the repairs it had promised and re-checks
  every holder; the rest of the ledger and the file list are on disk.
- **Browser storage (§12).** A tab's block store is in RAM, because the OPFS/IndexedDB
  backend isn't built yet, so a tab that acts as a holder forgets everything on reload.
