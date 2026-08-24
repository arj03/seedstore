# Seed store: a peer-to-peer storage layer for seedkernel

## 1. Introduction

Seed store is a peer-to-peer storage layer for [seedkernel](https://github.com/arj03/seedkernel). It lets any node donate whatever storage it has and store files across a set of peers, so that no single peer can make a file unavailable, peers can be offline for stretches without data loss, the system heals itself by moving data when redundancy drops, large files are sharded so size is bounded only by the swarm, and good citizens earn durability for their own data through direct reciprocity rather than a coin.

Seedkernel routes a wire protocol id to one bundle's confined guest over an encrypted, authenticated channel; it has no notion of a file and nowhere for a multi-megabyte one to live. So bulk data lives beside its dispatch path, referenced by a content hash. Seed store is that outside store: the kernel keeps routing the protocol id to the slot's guest, the bytes never touch its dispatch path, and everything here is built from the pieces seedkernel already provides — a channel that pins who is speaking, a claim to dispatch on, and a signed bundle that carries the code and its authority.

This design assumes a **closed, social network**: you store with and among peers you have a relationship with (friends, friends-of-friends, or an explicit storage group), not an open market of strangers. That assumption is what keeps the whole thing small — privacy and Sybil resistance come from the *shape* of the network rather than from added cryptographic machinery. The whole system is five ideas: **a social cohort, client-side encryption, content addressing, erasure coding, and a have/want exchange**.

**Design principles (inherited from the kernel, applied to storage):**

- The storage layer adds **no new kernel concepts**. It is one signed bundle — pure-transform WASM modules + a confined guest — and a small message vocabulary, gated by the channel that already pins every peer and the bundle policy that already admits every bundle.
- **Integrity comes from content addressing, not from signatures.** A block is named by its hash; a block either hashes to its name or it is discarded. This is what lets bulk transfer skip the per-message verify (§3).
- **Identity comes from the channel.** A peer *is* the kernel pubkey its authenticated channel pinned (§2). Reciprocity and authority key on that one identity; nothing is signed to establish it.
- **Redundancy is erasure coding, not replication.** Any *k* of *n* blocks reconstruct a chunk, so up to *n − k* holders can vanish with no data loss, at a fraction of replication's overhead.
- **Placement is by relationship, not by global address.** A chunk's blocks live on peers in your cohort, chosen by negotiation. Who holds what is discovered live from the cohort rather than pinned anywhere, and there is no global index — the absence of that index is a feature, not a gap (§5).
- **Confidentiality is structural.** The wire is encrypted; stored data is encrypted so holders only ever see ciphertext; and there is no public directory mapping content to holders.
- **Trust is local before it is global.** The base system rewards good citizens by direct, pairwise reciprocity you witness yourself (§13); portable, verifiable reputation across peers you have never dealt with is an optional layer (§20), not a baseline requirement.
- **The trusted base is small and separate from the logic.** Only the kernel's raw-byte capability backends — the flat-key `fs`, the node-key/entropy/clock authorities (`node`, `clock`), the raw `link` seam the transport bundle owns, plus the residual ungated `crypto/*` host transforms — are trusted host code; all storage *logic* — `codec`, `reputation`, and the `coordinator`/`cohort`/`repair` orchestration — is **confined** (WASM modules that import nothing, or the zero-authority JS realm), reaching I/O only through the service grants its bundle manifest declares. Trusting a node means trusting the small, stable base, not the larger, upgradeable logic (§2.1).
- **Browser nodes and long-running peers run the same protocol**, differing only in their `store` backend and default quota.

The reference composition stacks: the storage bundle (pure `codec`/`reputation` modules + the confined guest) → the shell — service grants (`node`, `fs`, `clock`, the transport's `_net`), the ungated primitives, the raw link and `fs` seams → the bundle loader and its admission policy → kernel.

---

## 1.1 Concepts at a glance

- **Block** — the one unit of stored data: a content-addressed slice of ciphertext of `B` bytes (block size `B` is a deployment tuning knob, §28, kept small so a whole block re-fetches cheaply, §8; no protocol constant bounds it — a transport's byte cap is operator policy, §3). `block_id = content_hash(block_bytes)`. A block is simultaneously an erasure-coding shard *and* the unit that moves on the wire.
- **Chunk** — a logical slice of a file: `k` data blocks plus `m` Reed–Solomon parity blocks = `n = k + m` blocks, any *k* of which reconstruct it. `(k, m)` is a single deployment-wide constant (§4.1).
- **Chunk descriptor** — the small *signed* record of a chunk's shape: its authentication tag and `n` block-ids. The only thing a repairer needs; signed by an author the cohort knows so a holder cannot forge it; both listed in the file's index and stored alongside every block (§4.3). It is also the file's **root**: a file's index is just an ordered list of these, chunked and placed like any other bytes.
- **Manifest** — the file's root object: the list of chunk descriptors plus the wrapped content key. The only thing you need to *read* a whole file. It does *not* name holders; which peer holds a block is discovered live from the cohort.
- **Cohort** — the bounded set of peers you have a storage relationship with. Discovery, placement, and repair all happen inside it. There is no global overlay.
- **Have/want** — the discovery primitive: peers tell each other which block-ids they hold or want. One round trip, no crypto protocol.
- **`store`** — the storage layer's own facade over the kernel's flat-key `fs` service (§16), whose backend reads/writes the node's donated bytes: filesystem on a server, OPFS/IndexedDB in a browser (§12).

```
file ─encrypt─► ciphertext ─slice into k─► data blocks ─RS(k,m)─► n blocks (k data + m parity)
                                                                   │ each block = one content-addressed ciphertext block
                                                                   ▼
                              placement: negotiate with cohort peers (offer / accept, §18)
                                                                   ▼
                    push block + chunk descriptor ──► distinct cohort peers      locate later via have/want
```

---

# Part I — The minimal system

This is the whole system you actually need: a durable, private, self-healing store for a cohort of friends or your own devices. It is complete on its own — every section in Part II is an optional add-on you reach for only when a specific assumption changes.

## 2. How it composes with the kernel

Nothing here changes the bundle loader, the guest seam, or claim routing (seedkernel §12.10). Storage shows up as three kinds of seedkernel object:

**The channel — which is also the identity.** Seed store needs an authenticated channel between peers, and the kernel's node↔node transport is exactly that on every byte-pipe (TCP, WebSocket, WebRTC): an authenticated key exchange, after which every frame is a forward-secret, individually-authenticated encrypted record attributed to the peer's key ([seedkernel §12.6](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md), [CHANNEL](https://github.com/arj03/seedkernel/blob/main/docs/CHANNEL.md)). That channel **is** storage's identity layer, and there is nothing else to it: a peer *is* the kernel pubkey its channel pinned. Every operation that needs "who" — who is offering, who is fetching, whose reciprocity standing moves — reads it off the channel rather than out of a signature, so there is no per-message signing and no separate account system. Storage reaches its peer RPC through the transport bundle's ordinary local service id `_net` — a claim under the transport's `services`, no privilege of its own, addressed by the storage bundle's signed `protocols` id (§12.10): a frame for that id lands in the storage slot, and only the storage slot's guest can see it. The live peer RPC is typed request/response on that channel (§3, §18), not module dispatch, and bulk blocks ride the same frame plane as hash-verified payloads of ordinary storage messages (§3, §18). A dedicated bulk channel is an optional performance upgrade (§22).

**The bundle — which carries the code, its names, and its authority.** Storage arrives as one author-signed bundle (seedkernel [§12.4](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)), and that one signature is what authenticates storage's code to a node that may have received it through any number of relays — the one place signing genuinely survives. The bundle holds the pure-transform WASM modules (`codec`, `reputation`), declared in the manifest's signed `modules[]` and reached by the guest by their **bare name** — `host.call("codec", …)`. There is no bind name and no global namespace: a module is a private value of its own slot, and the seam resolves a bare name against that slot's map (seedkernel §5.1, §12.2), so nothing on the wire ever names another node's module. It also holds the confined guest program and, in the same signed manifest, the *reach* that guest may use (`guest.requires`, seedkernel §12.4): an explicit, human-auditable list of host services (`node`, `fs`, `clock`) and local service ids (`_net`) declared by the author and gated **by service** by the shell. The pure modules — the codec (chunking, erasure coding) and the reputation math — hold **no** grants at all: they are computation, and the structural sandbox guarantees they can touch no I/O even if compromised. Deployments are kept apart not by names but by policy and scope: the admission policy's closed author set decides whose bundle may install (seedkernel [§12.5](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)), and the scoped signature (§16) keeps one deployment's signed objects from verifying in another's.

**Crypto — reused, never shipped.** Storage reuses the kernel's cryptography rather than bundling its own, so the only cryptographic-grade algorithm in storage WASM is **Reed–Solomon** (libsodium has no erasure coding); hashing and ChaCha20-Poly1305 use the kernel's residual ungated `crypto/*` transforms, while key-sealing is deliberately host-side over the same core libsodium (§16). A chunk descriptor is signed and checked through the host's *scoped* signing pair, and its detached authentication tag travels under that signature. Confidentiality *at rest*, which the channel's hop-by-hop encryption does not give (seedkernel §14), is therefore added client-side with no second crypto library (§4.4).

What the kernel deliberately does **not** give storage is anywhere for the bytes themselves to live: a module is a pure transform over a scratch buffer, and the channel moves opaque frames. Bulk data therefore lives beside the dispatch path, referenced by hash — the split §3 treats first.

---

## 2.1 Trust model: three tiers

Running a seed store node extends your trusted computing base (TCB) — but the design keeps the part you *must* trust small and separate from the part that changes. Three tiers, smallest-TCB-first:

**Tier 0 — kernel base.** seedkernel itself: the kernel plus the bundle loader that admits code under an admission policy. The root of trust; everything else composes on top.

**Tier 1 — I/O base (trusted).** The shell's raw-byte capability backends — the flat-key `fs`, the `node` authorities (scoped sign/verify, identity, entropy), the clock, and the raw `link` seam the transport bundle owns — plus the residual ungated `crypto/*` transforms over core libsodium (seedkernel §12.1). These *must* be trusted: they are the only code that performs real I/O. They are deliberately small, each bound to exactly one service, audited, and change rarely. This is the *whole* of what seed store adds to your TCB.

**Tier 2 — logic (confined, upgradeable).** Everything else: `codec`, `reputation`, and the `coordinator`/`cohort`/`repair` orchestration (§17). This is pure logic. It is **confined** — a WASM module imports nothing, a realm has no ambient authority — and reaches I/O *only* through the Tier-1 services its manifest's `guest.requires` names. The grant is signed content, not something the logic could declare for itself: the author names the services in the signed bundle manifest (§2, seedkernel §12.4), and the shell wires only those backends. So upgrading the logic does *not* re-grant trust: a new version (same author, seedkernel §12.5) runs in the same sandbox, structurally bounded to whatever its manifest grants — and because the grant is signed, versioned content rather than ambient authority, a widened grant is a visible manifest change, never a silent acquisition.

Two implementation forms satisfy Tier 2, both confined identically:

- **WASM** — the pure, hot compute (`codec`, `reputation`). The wasm sandbox is the boundary; admission and same-author upgrades are the bundle loader's job under its admission policy (seedkernel §12.4–§12.5) — an upgrade is not a separate mechanism, just a bundle whose manifest `version` is higher, signed by the author already recorded at the slot. A module holds no grants at all — pure computation with no I/O reach to govern.
- **Sandboxed JS** — the orchestration (`coordinator`/`cohort`/`repair`) *and* the holder side (admission, the sibling rule, content-addressing, quota, the store writes), which are awkward to express as a *synchronous* pure-transform module. They run in a **zero-authority JS realm**: a fresh context with *no* ambient authority, into which the host injects *only* the guest seam, never the backends themselves (seedkernel §12.3). CPU/memory are bounded by the host. Both roles run in **one** realm over a narrow-async seam (seedkernel §12.3): the initiator side `await`s a real network round trip, and the holder side is re-entered through the **same** one entrypoint to answer an incoming request *while* that initiator is parked mid-`await`.

The line that matters: **"trusting seed store" means trusting Tier 1 (small, stable, audited) — not Tier 2 (large, churning, upgradeable).** A buggy or compromised Tier-2 unit, of either form, can do nothing but compute and call the services it was granted; it can never reach I/O outside that grant, and an upgrade cannot silently widen it — a wider grant is a visible change to the signed manifest.

> **In the [seedkernel](https://github.com/arj03/seedkernel) runtime** these tiers map directly onto its [RUNTIME §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md): Tier 1 is the shell's raw-byte capability backends behind the one guest seam (§12.1–§12.2); Tier 2 is the seed store **bundle** — `codec` and `reputation` as no-grant WASM modules, the orchestration and holder side as zero-authority JS in its one realm (§12.3) — delivered as signed content (§12.4). A node *is* the generic shell plus this bundle; nothing storage-specific lives in the trusted runtime. See the [WASM implementation README](WASM/README.md) for how to run one.

---

## 3. The two planes: control and bulk

The kernel gives bulk bytes nowhere to live (§2), so they live beside the dispatch path, referenced by hash. That is the split, and the two halves are worth separating for a second reason: **they authenticate differently.**

**Control plane — small peer-to-peer messages.** Manifest root hashes, have/want exchanges, placement offers, fetch requests, repair coordination. The storage RPC between two cohort peers (§18) rides the kernel transport's authenticated channel and needs **no per-message signature**: the channel pins the remote's kernel identity and encrypts, integrity-protects, and replay-protects every frame itself (seedkernel §12.6), so the channel is the sender authentication.

What is *signed* is only what must outlive a channel or carry authority beyond it, and in Part I that is exactly **two objects**:

- **The bundle manifest** (seedkernel §12.4) — storage's own code, authenticated to a node that may have received it through any number of relays, where no channel can speak for the author.
- **The chunk descriptor** (§4.3), riding inside placement messages — signed by the file's *author*, not the message's sender, because a repairer must trust a chunk's shape having never spoken to that author, and the peer handing it over is precisely the party who would benefit from forging it.

Both are the same shape: authority that has to survive the hop it arrived on. (The optional tombstone, §25, and file head, §27.3, are two more of the same, when a deployment enables them.) Everything else on the wire is channel-authenticated — signed where authorization must travel, pinned by the channel everywhere else.

**Bulk plane — content-addressed blocks.** Blocks are **self-verifying by hash**, so they need no signature for integrity. In the base design they ride *inside* the same channel's messages — the push half of a `store` and the reply half of a `fetch` (§18) — as unsigned, hash-named bytes: the receiver verifies `content_hash(bytes) == block_id` against an id it asked for or admitted, and drops on mismatch — the hash, never the framing, is the authority. This stays entirely inside the kernel transport, inherits the channel's encryption and pubkey pinning, and avoids per-block verify cost because there is no signature to check. (A dedicated bulk data channel with its own raw framing, for higher throughput on large files, is an optional upgrade — §22.)

The rule is the same either way: **the control plane carries hashes and authorization; the bulk plane carries hash-named bytes that authenticate themselves.**

**No protocol constant bounds either plane.** Transfers are batched and windowed rather than per-block: one message carries many blocks, every message stays under a **per-transport byte cap**, and a peer keeps only a bounded window of capped messages in flight (§18, §28) — so round trips scale with peers rather than blocks. That cap (`maxMessageBytes`) is **operator policy, not protocol**: it is a per-node number, so a cohort may legitimately disagree on it — a holder bounds each `fetch` response by *its* cap, and a client whose cap is larger degrades to a few extra tail requests rather than failing (§18). Its floor comes from the transport (a WebRTC data channel reassembles only tens of KB; the kernel's own frame cap is 2 MiB, seedkernel §16.1) and its ceiling from memory: the real reason to keep it small is that a browser node must never hold more than a window of a large file at once. Memory and the transport size the window — never a fixed number in this spec.

---

## 4. Data model: files → chunks → blocks (and an index of the same)

### 4.1 Chunking and erasure coding (the redundancy primitive)

A file is encrypted (§4.4) and the ciphertext is cut into fixed-size **blocks** of `B` bytes — `B` a deployment tuning knob (§28), not a fixed protocol constant: no wire constant bounds a block (§3), and the only real pressure is to keep `B` small enough that a verification-fetch transfers a whole block cheaply (§8). Blocks are grouped into **chunks** of `k` blocks, and each chunk is **Reed–Solomon `RS(k, m)`** encoded into `m` additional **parity blocks**, for `n = k + m` blocks per chunk of which any *k* reconstruct it. A chunk is therefore just `k × B` bytes of data plus `m × B` bytes of parity, and every block — data or parity — is the same size and the same kind of object.

Defaults: `k = 10, m = 6` → `n = 16`, 1.6× storage overhead, surviving the loss of any 6 of a chunk's 16 holders. Compare naïve 3× replication, which survives only 2 losses at nearly double the cost. Reed–Solomon is **systematic** — the *k* data blocks are the ciphertext verbatim — so when all *k* data blocks are present a read just concatenates them and never decodes; the GF(2^8) decode runs only to heal around missing blocks. Encode/decode is simple, self-contained byte arithmetic that compiles to a small no-grant WASM module, and it operates on whatever bytes it is given — here, ciphertext (§4.4) — so reconstructing a missing block never requires the file's key.

`(k, m)` is a single **deployment-wide constant** (default `RS(10, 6)`, above), not a per-file choice — one value the whole store agrees on. Each chunk descriptor nonetheless records its own `(k, m, B)` (§4.3) rather than leaning on that constant: the geometry is a handful of bytes carried *under the author's signature*, so a descriptor is **self-describing** — a repairer (§9) needs no deployment config to audit and rebuild a chunk, a reader offsets and decodes by the *same* numbers with nothing to disagree, and a cohort can even run mixed geometry — while a holder still cannot forge those bytes (the signature won't re-verify). Pinned with `(k, m)` is the **RS construction** — field polynomial, generator matrix, and column order (default: systematic RS over `GF(2^8)`, primitive polynomial `0x11D`, Cauchy matrix in fixed column order) — because `(k, m)` fixes the *code* but not the *bytes*, and §9's keyless repair only holds when every peer's encoder emits byte-identical parity for a given `block_id`. Per-file durability dialing (cold archives at `RS(20, 20)`, hot ephemeral data at `RS(4, 2)`) is a deployment refinement, not part of the minimal core (§28).

**This alignment — `chunk = k blocks` — is what collapses the data model.** A block *is* an erasure shard *is* the unit on the wire, so there is no distinct "fragment" object to slice, list, or address; a chunk's descriptor is simply its list of `n` block-ids, and one block per message is always true by construction. (Fixed-size chunking is also the simplest; a deployment that wants cross-file dedup can swap in content-defined chunking, at the cost of variable-length blocks that no longer map one-to-one onto shards.)

**Every chunk is coded at its own `k`.** A chunk carries `kc = max(1, ceil(plaintext / B))` data blocks — the chunk's own `k`, ≤ the deployment's `k` — and is RS(`kc`, `m`) encoded. At `kc ≥ 2` this produces `kc + m` distinct blocks. At `kc = 1` RS(1, `m`) degenerates: its parity blocks are byte-identical to the lone data block (parity ≡ data over GF(2⁸)), so the codec is skipped and the one block is placed on `r = m + 1` distinct peers instead. Per-chunk `k` means a partial chunk is never padded to the deployment's `k`; it pays `d + m` blocks instead of `k + m`, which strictly dominates both replication and padding for all `d ≥ 2`. The descriptor is self-describing (§4.3): each chunk records its own `(k, m, B)`, so a reader offsets and decodes by the chunk's own numbers.

**Coded and replicated are one shape, not two models.** Every descriptor lists exactly `n = k + m` ids. Where the code degenerates the descriptor simply lists its lone block `m + 1` times, so **multiplicity carries the replica count** and the two cases are the same object read the same way:

```
coded (k ≥ 2)   block_ids = [b₀ … b_{k-1}, p₀ … p_{m-1}]   n = k+m distinct ids, one holder each
k = 1           block_ids = [b₀, b₀, … b₀]                  n = k+m listings of one id, m+1 holders
```

There is nothing to branch on. The placement slots *are* the listed ids (one distinct peer apiece), a read takes any `k` **distinct** listed blocks, and the health of either is one number by one formula — the loss margin `Σ min(live_holders, multiplicity) − k` (§8), where the `min` is what stops an over-replicated block inflating the margin past what its author asked for. Replication at `k > 1` does not exist — RS(`d`, `m`) strictly dominates it for all `d ≥ 2`. A repairer reads `k`, `m`, and the id list off the signed bytes and knows the chunk's shape, its per-block copy target, and its low-water mark (§8) without consulting deployment config, which is what lets a mixed-geometry cohort repair each chunk back to the count its own author signed. (`m = 0` is the one place the two coincide: no parity and no second copy are the same zero-redundancy chunk.) The one rule this shape needs: a holder **declines a block it already holds**, since a repeated id's `m + 1` slots are `m + 1` peers, and quietly overwriting a copy would burn a slot without adding a holder.

### 4.2 Blocks are content-addressed

Each block is content-addressed: `block_id = content_hash(block_bytes)`. Content addressing makes every block **self-verifying**: a receiver recomputes the hash and rejects anything that doesn't match, so a malicious holder cannot return corrupt bytes undetected, and no signature is needed on bulk data (§3). Because the bytes are ciphertext (§4.4), a `block_id` is the hash of an encrypted blob — opaque and unguessable to anyone who has not handled that exact file.

### 4.3 The signed chunk descriptor (and why there is no manifest object)

**One** small object describes a file: the per-chunk **descriptor**. What used to be a second object — the manifest — is just an ordered list of these, stored the same way the file body is.

**The chunk descriptor** is a chunk's *shape*, and it is the only thing a *repairer* needs (§9). *Reading* a file needs the whole index and the content key and is gated to the sharing group; *repair* needs much less, and we want it possible for far more peers, so each stored block carries its chunk's descriptor. This descriptor **must be authenticated**: `block_id` covers a block's *bytes* but says nothing about the *relationships between blocks*, so an unsigned descriptor — still a valid string of bytes, content-addressing notwithstanding — could be altered by a malicious holder to misdirect or suppress repair (point a repairer at blocks that don't exist, hide that a chunk is decaying). So the descriptor is **signed by the file's author** (the §2 identity):

```
descriptor D:
  tag                  // leading format tag — distinct per signed storage format (§16)
  level                // 0 = the file's own ciphertext; ℓ > 0 = an index chunk over
                       //   level ℓ−1 (below). Doubles as the §4.4 nonce domain.
  k, m, B              // this chunk's own geometry — self-describing (§4.1), so a
                       //   repairer needs no deployment config and reads never disagree
                       //   (m = losses survived, by parity or by copies — §4.1)
  tail_bytes           // how many of this chunk's k×B plaintext bytes are real; the
                       //   rest is zero padding. This is what replaced the manifest's
                       //   file_size — a reader trims each chunk by its own signed number.
  block_ids[0..n)      // ALWAYS n = k + m. Coded: 0..k data, k..n parity, one per peer.
                       //   k = 1: the same id listed m+1 times, one per peer (§4.1).
signed by the file's author (the §2 identity)
```

Every peer that accepts a block first verifies its descriptor: the author's signature over it is valid — checked over the scoped, tag-led preimage of §16, which every node running the same bundle reconstructs identically — **and the key that signed it is an identity the holder's cohort knows** (§5.1), and the block's own `block_id ∈ block_ids`. That second check is what makes the first mean anything: the envelope carries the author's public key *inside itself*, so a signature verified against that key alone proves only that somebody held some private key — any cohort peer could mint a fresh keypair, self-sign a descriptor with a truncated sibling list, and concentrate a chunk on itself. Anchoring the author to a known peer costs nothing and makes a forgery **attributable**, which is reciprocity's job (§13) rather than new machinery. The price is that a cohort is mutual: a writer must be in its holders' rosters, and a peer evicted from the roster can no longer have its files repaired. A block that fails either check is rejected outright. The descriptor is therefore **mandatory on every placement message** (§18): a block offered or pushed without one is malformed, not a block admitted on quota alone — otherwise any cohort peer could put arbitrary bytes on a holder while sidestepping this check and the sibling rule (§6) with it. Because a block is exactly the descriptor's signed `B` bytes, that geometry is also what a holder charges against its quota (§14). A holder therefore cannot alter the descriptor it serves — the signature won't re-verify — nor substitute its own key, since authority is bound to a *known* author (the same trust root that authorizes removal, §11). Crucially, this check needs only the author's *public* key, never the read key, so keyless repair (§9) is preserved — and a repairer further re-certifies its own output against the signed `block_id`s, so even a bad descriptor cannot mint garbage (§9). The descriptor thus discloses a chunk's size and shape to anyone storing a piece of it — the disclosure accepted in §15 — but never its contents, and never a forgeable instruction.

**There is no manifest.** A chunk's plaintext is either file bytes or a list of descriptors — and a file is one descriptor. That is the whole data model; everything below follows from it.

A descriptor list is self-delimiting and headerless:

```
[ len u32 ‖ descriptor ] …
```

no version (the descriptor's own tag is the version), no `file_size` (each descriptor signs its `tail_bytes`), no `enc: { alg }` (the format fixes it). Those bytes are placed by **exactly the call that placed the file body** — same `B`, same `(k, m)`, same windowing, same placement, same admission, same repair — and if they came to more than one chunk, so are the descriptors *that* produced. What is left is one descriptor: the file's **root**, and the whole of what a reader is handed alongside `K` (§4.4). A file that fits one chunk has no index at all — its own descriptor *is* the root — and a reader tells the cases apart by the signed `level`.

**This is iteration to a fixed point, not a data structure.** It is bounded and it is shallow, because one chunk holds thousands of descriptors:

| `level` of the root | covers, at `k=2, m=2, B=256 KiB` |
|---|---|
| 0 — the root is the file's only chunk | up to 512 KiB |
| 1 — one list of descriptors | up to 1.1 GB |
| 2 | up to 2.5 TB |
| 3 | up to 5 PB |

So the loop runs zero times for a small file, once for almost everything else, and has no third iteration below petabyte scale. The one thing it asks of a deployment is that a chunk hold **two** descriptors — `k × B ≥ ~2 × 237 B`, cleared ~2000× at production geometry — which is a property of `(k, B)` alone and so is checked once when a PUT opens, never discovered mid-placement.

The cost of all this is one thing: what you hand a reader is a variable-length signed descriptor (~237 B at `RS(2,2)`) rather than a 32-byte hash. What it buys is three: there is no manifest object, no manifest codec, and no manifest nonce domain; there is no `k = 1` placement special case that made one "block" as large as the whole manifest; and **the size ceiling is gone**. The old single-block manifest crossed a 1 MiB message cap at roughly a 2 GB file and a WebRTC node's ~48 KiB cap at roughly 100 MB, and past that degraded rather than failing — one over-cap `STORE`, quota charged for a multi-MB "block", `serve_fetch`'s first-block rule serving it anyway. Now every block on the wire is exactly `B` bytes at any file size. (A *single* list, with no fixed point, would not do: it caps at 1.1 GB at production geometry — below what the broken manifest managed — and at 1.5 MB on a WebRTC node. The fixed point is what removes the ceiling rather than lowering it.)

Crucially, the index says *what* blocks a file is made of, never *which* peers hold them — that is discovered live via have/want (§5), so the holder map stays current under churn and repair instead of going stale in a fixed file.

The descriptor carries no chunk index: a chunk's position in the file is given by its order in the index level that lists it, and a block-holder repairing a chunk never needs the position — only the sibling block-ids and the chunk's own `(k, m, B)` — so those, unique-by-content, are the whole identity. The same descriptor object thus lives in **two homes**: inside the (encrypted) index, so a reader gets every chunk's shape at once; and in the clear alongside each stored block, so a repairer who lacks the index still has its chunk's shape and can verify it from the author's public key alone. Only the second home is load-bearing for the signature. On the read path the check is redundant — a reader holds the root and reaches every level below it through content-addressed ids (§4.2), so a tampered index fails its hash long before it is parsed — which is precisely why the anchor above belongs at *admission*, where authority is actually being granted. It is small and signed, so duplicating it is cheap and tamper-evident in both places.

### 4.4 Encryption (the load-bearing privacy mechanism)

The kernel channel encrypts a link hop-by-hop, but nothing it carries stays confidential once written to a holder's disk. In this design, **encryption is what makes the closed network safe** — it lets you store on cohort peers who can read nothing, and it makes block-ids opaque. Seed store encrypts **client-side before erasure coding** through the kernel's existing ChaCha20-Poly1305 transform (§2, §16), not bundled crypto. Ciphertext stays length-preserving for erasure coding; the 16-byte authentication tag travels separately inside the author-signed chunk descriptor, so every stored block remains exactly `B` bytes and the systematic data blocks remain ciphertext verbatim:

- Generate a random per-file **content key** `K` and seal each padded chunk under `K` with ChaCha20-Poly1305-IETF, using a deterministic 12-byte nonce containing `level ∥ index` — the chunk's own signed index-tree level (§4.3), plus its chunk index within that level. A fresh random `K` for every file makes that nonce namespace unique; within one file `(level, index)` never repeats. Split the result into same-length ciphertext plus its 16-byte tag: slice and erasure-code only the ciphertext, and carry the tag in the signed descriptor. Holders therefore still store exact `B`-byte ciphertext blocks and learn nothing about content. Index levels are encrypted under `K` the same way; the level byte separates an index chunk from a body chunk at the same index, and key rotation (§23) mints a fresh `K`.
- **Sharing a file is sharing the key, not moving bytes.** The owner sends a recipient `{ root_descriptor, seal(K → recipient_pubkey) }` over the authenticated channel — `K` sealed to the recipient's kernel public key (libsodium `crypto_box_seal`, converting the Ed25519 kernel key to X25519). The key is never stored in clear on holders, which is what avoids the circularity of putting `K` inside an index that `K` encrypts. Re-sharing is one more sealed copy; revocation that must deny future reads rotates `K` and re-encrypts (§23).
- Random per-file keys mean two different files never produce colliding ciphertext, so a `block_id` is meaningful only to someone who has handled that exact file. Convergent encryption (key = hash(plaintext)) is an opt-in for deployments that want cross-user dedup and accept its equality-leak (§24).

**Why the tag is detached.** Content addressing still rejects a modified block before decryption: every block must hash to an author-signed `block_id` (§4.2–§4.3). The AEAD tag adds an independent keyed check, including clean rejection of a wrong content key. Keeping that tag in the signed descriptor instead of appending it to ciphertext preserves the useful storage invariant that every shard is exactly `B` bytes; repair remains keyless because it copies the signed tag without needing to verify it under `K`.

**Post-quantum note: the sealed key is the harvest-now artifact.** The sealed copies of `K` are the one piece of this design a cryptanalytically-relevant quantum computer retroactively unlocks: `crypto_box_seal` is X25519 confidentiality over the converted kernel key, so a recorder who stores a sealed `K` today decrypts it when the DH problem breaks — and unlike the channel (seedkernel §14.1), no link rotation re-encrypts it. A sealed `K` is durable by design, held in keystores for as long as the share lasts, which is the longer sensitivity horizon that makes at-rest ciphertext the worse case. The exposure is bounded by what a holder keeps, and the fix is already the design's own shape: **re-sharing is one more sealed copy (§4.4), so a PQ migration is a bulk re-share — the owner mints one fresh seal per recipient per file, nothing else changes**. What a PQ seal needs that does not exist yet is a recipient's ML-KEM public key: ML-KEM now demonstrates the right packaging inside the transport bundle rather than in the kernel host table, but a recipient KEM key still needs an address, published key, or share field. Until then, holding sealed keys past a multi-year sensitivity horizon is a deployment choice, not an accident: rotate `K` (§23) and re-seal, or accept the clock.

---

## 5. Discovery: a social cohort with have/want

We need to answer two questions — *which peers should hold a block?* and *who currently holds it?* — without a public, queryable index that would map content to holders. The closed-network assumption (§1) lets us answer both with almost no machinery.

### 5.1 The cohort

A node keeps connections to a **bounded set of peers it has a relationship with** — direct contacts plus, optionally, a hop or two out. There is no global index or routing table; nothing about who-holds-what exists outside your cohort. New peers join the way Scuttlebutt peers do, by introduction or via a rendezvous point. Cohort size is tens to low hundreds, which is what keeps every operation here cheap.

### 5.2 Have/want is the whole discovery layer

- *Who currently holds block B?* — ask the cohort. A have/want carrying the block-ids turns up whoever has them right now; nothing is pinned in advance, so the answer is always current.
- *Are there extra replicas, and is a given peer still holding its blocks?* — the same one-round exchange: "I want these `block_id`s" / "I have these `block_id`s." No lookup walk, no cryptographic protocol, no rate-limit machinery.

A have/want only ever **names ids the asker already knows** — ids it holds, or was handed in a descriptor; the reply confirms or denies exactly those and never returns a peer's full inventory. There is no "list everything you have" message anywhere in the protocol, so files cannot be enumerated — *don't share = can't probe*.

Block-ids are hashes of random-key ciphertext (§4.4), so to a peer outside a file's sharing group they are opaque noise, and on the wire they are encrypted. The only parties who can interpret a have/want entry are those who already hold the file's key — i.e. people you deliberately shared with.

Note that have/want is **advertisement, not proof**: a peer can answer "have" to a block it cannot actually serve. §8 closes that gap by backing the redundancy count with occasional verification-fetches.

### 5.3 What this is, and is not

This is deliberately **not an open market**: strangers cannot find or serve your data, because there is no global index and nothing to query. That absence is the privacy property we want. The cost is that storage is confined to your cohort — the trade we are choosing.

What leaks, and why it is acceptable here: a peer you exchange have/want with learns which block-ids you hold or want *of files you have already shared with it*, and roughly your inventory size. These are disclosures to people you have already chosen to store with, about files you have already shared with them. The full leak inventory and the optional hardening for less-trusted cohorts are in §15 and §23.

---

## 6. Writing a file (PUT)

1. **Chunk & encrypt.** The owner generates a random content key `K` (via `node/random`, §16) and feeds the file to the `codec` (no grants) block-by-block, encrypting each chunk under `K` (§4.4).
2. **Erasure-code.** The `codec` (no grants) turns each chunk's *k* data blocks into *m* parity blocks, computes all `n` block-ids, and forms the chunk's descriptor, which the owner signs (§4.3). A file too small to fill a chunk skips the codec and lists its lone block `m + 1` times instead, which is the same descriptor shape (§4.1).
3. **Place by negotiation.** For each block, the `store.coordinator` picks candidate cohort peers — ordered by reciprocity standing (§13) and current reachability — and sends an `offer` (block_id + the signed descriptor — §18; the block's size is the descriptor's own signed `B`, so it is never a separate field a sender could disagree with). A peer with free quota and willingness accepts; a decline moves the coordinator to the next candidate. There is no global placement function; placement is a short private negotiation within the cohort.
4. **Push.** On accept, the coordinator streams the block over the bulk plane (§3) together with its signed chunk descriptor, so the holder can verify it and later help heal the chunk.
5. **Place the descriptors too.** The signed descriptors, in order, are themselves bytes: run them through steps 1–4 unchanged, and if that came to more than one chunk, run *its* descriptors through as well, until one is left (§4.3). Usually this happens once and never again. No separate manifest is built, replicated, or capped. Descriptors list block-ids, not holders; which peer took which block is rediscovered live via have/want, so placement can shift under repair without anything going stale.
6. **Publish.** The **root descriptor** is what the owner keeps and shares, with `K` sealed to each recipient (§4.4), over the authenticated channel to that recipient. The share needs no signature of its own: the channel pins who sent it (§3), and the seal is what keeps `K` secret in any case.

The `n` blocks of a chunk are placed on **distinct peers** (the coordinator enforces no-two-blocks-of-a-chunk-same-holder), so losing one peer costs at most one block of any chunk — the core of the §10 invariant. Because every `offer` carries the chunk's descriptor (§4.3) — signed by an author the holder's cohort knows — a holder enforces this itself, declining an offer for a chunk it already holds a sibling of, **including a repeat of the very same block** (§4.1). So the invariant survives a careless or malicious placer, a repairer (§9) included, not just an honest coordinator. Where the deployment can tell peers apart, placement also spreads a chunk across distinct *social clusters* (one person's devices, one tight friend-group), so a correlated failure or collusion costs one block rather than several (§10).

---

## 7. Reading a file (GET)

1. **Resolve the root.** You were handed the root descriptor and the sealed `K`. If its signed `level` is 0 it already describes file bytes and you are done. Otherwise read that chunk by steps 2–4 below — the same fetch, verify, decode, decrypt — and its plaintext *is* the descriptor list one level down; repeat, which in practice means once. **Each step must strictly decrease `level`**, and a reader enforces that rather than assuming it: whoever supplied `(root, K)` can construct valid AEAD at every level, so authentication alone does not stop a level-ℓ root from naming a level-ℓ list. Without the check a reader can be walked through an arbitrarily long non-descending chain. With it, the descent is bounded by the `level` byte. The file size is the sum of the leaves' signed `tail_bytes`. No *signature* check is needed here: the root is in your hand and everything under it is content-addressed (§4.2).
2. **Locate blocks.** Send a have/want to the cohort for a chunk's block-ids. You need any *k* of *n* per chunk, so race requests to the *k* best-scoring reachable peers that answer; if some are offline, the same have/want surfaces any extra replicas repair has created.
3. **Fetch & verify.** Stream blocks over the bulk plane; each is checked against its `block_id` (self-verifying, §4.2).
4. **Decode & decrypt.** If all *k* data blocks arrived, concatenate them (systematic RS, no decode); otherwise RS-decode any *k* blocks to recover the chunk ciphertext. (A `k = 1` chunk, §4.1, has no parity: fetch its one block from any live holder — never a decode.) Decrypt under the chunk's own `level` and index, trim to its signed `tail_bytes`, concatenate chunks.

Because any *k*-of-*n* suffices, a read succeeds even with up to *m* holders offline or unwilling — no peer is on the critical path.

---

## 8. Availability and offline tolerance

Peers are expected to disappear and come back. The protocol distinguishes a transient blip from real loss so it doesn't churn data on every disconnect — and it does so by direct observation within the cohort, not by a global refresh scheme.

**How liveness is observed.** Any block-holder (or the owner) periodically sends a have/want for a chunk's block-ids and notes who answers. There is no record to refresh and nothing to expire, so the picture is always current. Because have/want is only advertisement (§5.2), the picture is **backed by occasional verification-fetches**: a holder is counted as truly holding a block only if it has recently *served* that block (or a sampled one of its blocks) and the bytes hashed to their `block_id`. This proves a block is *retrievable*, not that the peer *dedicated storage* to it — because a block is small, a holder can pass by re-fetching a replica or RS-regenerating from *k* siblings on demand (§10), so `live_blocks` counts **availability**, not *n* independent copies. Two cheap measures keep that gap from being worth exploiting: the fetch is **latency-bounded** (regeneration needs *k* round-trips and a decode; a stored block, one disk read), and its cadence is tuned (§28) so faking costs roughly what honest storage costs. A peer that advertises blocks it cannot serve is detected the same way and treated as not holding them — which also feeds reciprocity (§13).

**Three states per holder of a block:**
- **Live** — recently reachable *and* recently served a verification-fetch for the block (or a sampled sibling).
- **Suspected** — unreachable within a **grace window** `G` (default 24 h). *No repair.* This is precisely "a node may be offline for a period": a laptop closed overnight, a phone in a tunnel, a server rebooting all sit here and recover for free when they reappear.
- **Lost** — unreachable beyond `G`, or repeatedly failing to serve a block it advertises. Eligible to be counted as missing for repair. (A node may first corroborate the unreachability with a second observer to avoid acting on a one-sided eclipse, but it need not: repair is idempotent (§9), so acting on a single observation is safe — at worst it briefly over-replicates.)

Grace lives in the observer's bookkeeping, not on the wire — and skipping it is *safe*, just wasteful: repair is idempotent (§9), so a node that treats every failed audit as Lost at once merely re-spreads blocks a sleeping laptop still holds, and the surplus is reclaimed as ordinary over-replication (§14). The reference implementation currently takes exactly that trade — it keeps no liveness state and heals on first miss — so `G` is a knob of the design (§28), not yet of the implementation; add the Suspected tier when cohort churn makes the extra repair traffic matter.

**Redundancy measure.** A chunk's health is one number by one formula, its **loss margin**: how many further losses it survives right now, computed straight off the signed id list (§4.1) —

```
margin = Σ over distinct listed blocks of  min(live_holders, times listed)  −  k
```

For a coded chunk every id is listed once, so each term is 1-if-live and the margin is the familiar `live_blocks − k`, healthy at `n = k + m`. For a `k = 1` chunk the single id is listed `m + 1` times, so the margin is `min(copies, m + 1) − 1`, healthy at `r = m + 1` copies. The `min` is what makes one formula correct for both: an over-replicated block contributes only what its author asked for, so surplus copies can never mask a chunk that is actually thin. Either way the margin is `m` on a fully-healthy chunk and `0` one loss from death, so the same number reads the same way whatever the chunk's `k`. Repair triggers on a **low-water mark** strictly above the death line (§9), never waiting until the chunk is one loss from it.

**Browser nodes specifically** are treated as low-uptime, often-Suspected holders: they may serve reads and act as extra cache while present, but the durable *m* leans on longer-lived cohort members. A deployment can tag node longevity so placement prefers steady peers for durability and lets browsers absorb read load.

---

## 9. Self-healing / repair

Repair is per-chunk, and it is performed by the chunk's own **block-holders**. Anyone holding a block also holds that chunk's signed descriptor (§4.3) — the sibling block-ids and the chunk's own `(k, m)` — which is all you need to audit and rebuild it, with no deployment config to consult, and reconstruction runs on ciphertext, so a repairer never needs the file's key (only the author's public key, to check the descriptor). The sharing group *reads*; any block-holder *repairs*. No peer is special and no one is appointed; the work gets done by whoever notices first.

This is what makes repair redundant. The peers able to heal a chunk are exactly the peers storing it — about `n` of them — so repair survives as long as a single block-holder is online, and the repair-redundancy automatically scales with the durability `m` you chose. (The alternative, tying repair to whoever can read the file's index, would make a private file's owner the sole possible repairer — a single point of failure for healing even when the bytes themselves are amply redundant.)

**The repair loop (run by any block-holder on a jittered interval):**
1. Send a have/want to the cohort for the chunk's block-ids (§5), and sample a verification-fetch or two (§8) to confirm advertised blocks are actually retrievable → the live holders of each block, and from them the chunk's **loss margin** (§8).
2. If `margin < ⌈m/2⌉` — half the redundancy spent — repair is needed. One rule and now one formula (§8), since both cases are measured against the same `m` the descriptor signs. Nothing here is deployment config; a repairer computes the mark from the chunk in hand.
3. **Avoid duplicate work** with the jittered timer alone: the peer whose timer fires first repairs, and the others — firing later — see its freshly placed blocks in have/want and stand down. No claim, no coordinator, no promise to track: repair is **idempotent**, because the deterministic re-encode (§4.1) regenerates the *same* content-addressed block-ids, so even if two peers heal the same chunk at once they converge on identical blocks and the surplus is reclaimed as ordinary over-replication (§14). Jitter only makes the overlap rare; correctness never rides on avoiding it. (Dropping the claim also drops the grief vector it created — a peer claiming chunks it never heals — so there is nothing left to police.)
4. The repairer tops every block short of its target back up — the target being how many times the descriptor **lists** that id (§4.1), which is `m + 1` for a `k = 1` chunk's lone block and 1 for each of a coded chunk's — from a copy it verified in step 1. A **coded** block that no live holder serves at all has no copy to lean on: the repairer fetches any *k* retrievable blocks (each self-verifying by its `block_id` on arrival, §4.2), reconstructs the chunk's ciphertext, and re-encodes only the **missing** blocks. (A `k = 1` chunk has no parity to rebuild from — its other copies were the redundancy — so it can only be copied while one survives, which is exactly what the `min` in the margin tracks.) Because RS re-encode is deterministic — the construction is pinned deployment-wide (§4.1), so every encoder emits the same bytes — **each regenerated block must hash to its already-signed `block_id`** before the repairer trusts it — this certifies the reconstruction keylessly and catches any wrong input or decode error, so a poisoned descriptor can never make repair mint or propagate garbage. It then places the regenerated blocks on fresh cohort peers (§6 steps 3–4) with the signed descriptor, skipping current holders so redundancy spreads to new peers.
5. The new blocks are immediately discoverable via have/want; redundancy returns to full — `n` live blocks, or `r` copies — with no change to the file's index, since the index never named holders.

**Moving data on availability change** is the same loop run proactively: if a peer sees the cohort thinning (many Suspected/Lost holders, e.g. a correlated outage), it re-spreads blocks toward healthier peers before a chunk crosses low-water.

**The one real cost**: a chunk can only be healed while at least one of its block-holders is online within a repair interval. With about `n` holders that is a weak requirement, but it can still fail if a chunk's holders are *all* low-uptime and go dark together (e.g. an all-browser cohort overnight). Placing at least one durable peer among each chunk's holders removes the risk — which is also what §8 recommends for the durable `m`.

**Repair amplification is bounded** by erasure coding: regenerating one lost block costs *k* block-reads and one chunk reconstruction, and only the lost blocks are rebuilt. (When that *k*-read cost dominates, a Locally Repairable Code cuts it — §21.) A `k = 1` chunk (§4.1) is cheaper still: repair is a single block copy from any live holder, with no reconstruction at all.

---

## 10. The redundancy invariant: no peer can make data unavailable

This requirement is **structurally bounded, but socially realized.** What the structure guarantees absolutely is that the *blast radius* of any one peer is small and that cheating is *detectable in principle*; what turns that into a durability number is the closed cohort (§1). First, what structure gives:

- **No block is unique.** A chunk survives on any *k* of *n* blocks, and the *n* blocks live on distinct peers (§6). One peer holds at most one block of a given chunk, so its disappearance — or its refusal to serve — costs at most one block. You need *more than m* peers to fail or defect simultaneously to lose a chunk. (A `k = 1` chunk, §4.1, is the same bound by another route: its id is listed `m + 1` times, so it too lands on `m + 1` distinct peers and survives any *m* losses.)
- **No metadata is unique.** A file's index is stored exactly like its body — chunked, coded or `m + 1`-way listed, spread over distinct peers (§4.3) — so the metadata inherits the same `k`-of-`n` bound as the data, and there is no single index server. The holder map is not stored at all; it is recomputed live.
- **No single repairer is required.** Any of a chunk's ~`n` block-holders can heal it (§9), on ciphertext, without the read key; removing any one removes no capability. Repair-redundancy is therefore as high as the data-redundancy *n*, not gated on a small set of readers. And because each chunk's shape travels as an **author-signed descriptor** whose author must be a peer the holder knows (§4.3), no holder can misdirect or suppress repair by tampering the header, nor by re-signing one under a fresh key of its own — an altered descriptor fails its signature check and an unanchored one fails admission.
- **Withholding is detected and routed around.** A holder that stops serving fails its verification-fetches (§8), loses reciprocity standing (§13), and gets skipped in future placement; its unreachability tips it to Lost and triggers repair. Active malice degrades to the same path as passive offline-ness.
- **Corruption is impossible to hide.** Content addressing (§4.2) means a tampered block fails its hash check and is discarded; the reader simply fetches another block.

What structure does **not** give — and what it instead trusts the closed cohort for — are the three assumptions that turn that bounded blast radius into an actual durability number:

- **Independence of copies.** A verification-fetch (§8) proves a block is *retrievable*, not that a peer *dedicated storage* to it: because a block is small, a holder can pass by re-fetching a replica or RS-regenerating from *k* siblings on demand (it carries the descriptor, §4.3). So `live_blocks` measures *availability*, not *n* independent copies — holders that re-serve one origin fail together. An honest cohort has no motive to do this, and §8's latency-bounded, cadence-tuned challenges make faking cost about what honest storage costs, but copy independence is finally *trusted, not proven*.
- **No collusion past the budget.** Fewer than *m* of a chunk's holders fail or defect *in concert* within a repair interval — with jointly-controlled or socially-correlated peers counted as one failure domain, which is why placement spreads across distinct social clusters and not merely distinct keys (§6).
- **A reachable repairer.** At least one of a chunk's block-holders is online within a repair interval, or nothing can heal it (§9).

Sizing `(k, m)` — and with it the low-water mark, which is derived from `m` — and the repair cadence against your cohort's real churn *and* against how many members could plausibly fail or collude together is the deployment's durability dial (§28). The first assumption is the one to keep in view: in a friends-or-devices cohort it costs nothing, but in a less-trusted pool it is exactly what the §23 hardening — and, if you must *prove* rather than trust storage, a heavier proof-of-storage layer — would have to shore up.

---

## 11. Removal

In a store where other people hold your bytes, you cannot force a remote peer to delete on command. The deletion the system actually **guarantees** is crypto-shredding; reclaiming the disk it occupies is then a matter of letting the data age out.

**Crypto-shredding — the guarantee.** Because every file has a random per-file key (§4.4), destroying that key makes all of its ciphertext blocks — its index levels included — permanent noise to everyone, immediately and irreversibly. The owner and sharing group drop the sealed key from their keystores; whatever ciphertext lingers on holders is unreadable forever. Its scope is exact: it denies *future* reads to everyone who discards their key, but it cannot reach a member who kept a sealed copy of `K` (or who already saved the plaintext) — for them a "deleted" file stays readable. Crypto-shredding is thus a guarantee about *confidentiality going forward among key-discarding peers*, not about erasure — and that is the only deletion the system can actually promise.

**Reclaiming the bytes — by eviction.** Once a file's key is gone, nobody reads or repairs its blocks, so they go cold and age out as orphans under ordinary eviction (§14). This needs no new mechanism and no authority check, because crypto-shredding has already made the data worthless — but it is **best-effort, not guaranteed**, and unhurried: disk frees over the eviction horizon, not on command. A holder who keeps `K` and keeps running repair (§9) can sustain a shredded file indefinitely, since repair needs neither key nor permission; the signed tombstone of §25 *asks* holders to drop the blocks and stop repairing, but an adversarial holder can ignore it. There is no way to force erasure on a peer who holds your bytes and refuses — against an honest cohort the bytes age out, and against a motivated insider the confidentiality leg above is the real guarantee.

**Authority.** Who may crypto-shred is just who holds the key: the owner and anyone they shared it with drop their own sealed copy. A member who no longer wants a file likewise just drops its copy and stops repairing — it cannot destroy the key for everyone.

The flip side — making a key *survivable* rather than promptly destroyable, by splitting it across the cohort so a quorum can recover it — is the optional Shamir layer of §26, which deliberately weakens this guarantee for files that want it.

A deployment that wants *prompt*, signed space-reclamation — actively telling holders to drop the bytes and stop repairing, rather than waiting for eviction — adds the optional **tombstone** layer of §25.

---

## 12. Donating storage

"Donate whatever storage you have available" is the storage layer's `store` facade over the kernel's flat-key `fs` service, plus a host-configured quota.

**The `store` facade (§16)** exposes `put(block_id, bytes)`, `get(block_id) → bytes`, `size(block_id) → n | −1` (existence is `size ≥ 0` — there is no separate `has`, mirroring the kernel's `fs/size`), `delete(block_id)`, `list()`, and `stat() → { quota, used, free }`. It is nothing but the `fs` service's names under storage's own key namespace: like every granted service it exists in a realm only if the bundle manifest declares it (§2.1), so only logic that may use `fs` can reach disk at all. A holder stores opaque `(block_id → ciphertext)` pairs plus the small signed descriptor (§4.3): it needs no file key and learns nothing about what it is holding beyond the chunk's shape.

**Backends differ by host, protocol does not:**
- **Long-running peer:** a directory on disk; quota is a config number; effectively always Live.
- **Browser node:** OPFS or IndexedDB; quota bounded by the browser's storage budget; eviction-aware (treat browser-evicted blocks as Lost and let repair handle them). The browser shell exposes a "donate N GB" control to set the quota.

**Quota honesty is enforced, not assumed.** A node advertises free space, but no peer trusts the number — it trusts the node's track record of *actually serving the data it accepted* (§8, §13). Lying about capacity gets you data you then fail to serve, which costs reciprocity standing. The `store` facade's `stat()` is for the owner's own accounting and admission control (declining `offer`s when full), not a network-trusted figure.

---

## 13. Reciprocity: rewarding good citizens without a coin

The reward for being a good citizen is **durability for your own data and good service from your cohort**, and the thing that earns it is *reliably holding and serving data for others*. No token, no ledger, no global reputation object — just **direct, pairwise reciprocity**, which in a closed cohort is all you need and is inherently Sybil-proof: you score only peers you have actually interacted with, so identities a peer invents to inflate itself never enter your view.

### 13.1 The local score

Each node keeps, per peer, a small **decayed reciprocity balance** built only from things it has *witnessed directly*:
- **Service received** — blocks that peer has reliably held and served for you, confirmed by the verification-fetches that already back repair (§8): occasionally you fetch a random block you placed with a holder and check it hashes to its `block_id`. A pass raises the holder's score; a miss decays it. This reuses the ordinary fetch path — there is no separate challenge protocol and no proof object to store.
- **Reciprocity** — netted against how much you currently store *for* that peer, so the score reflects a running give-and-take.
- **Recency** — old observations decay, so a peer that stops serving fades, and the state never grows without bound.

`reputation.score(pubkey) → score` is a read-only query over these counters, used by placement (§6), by holders deciding whether to accept an `offer` (§18), and by readers choosing whom to fetch from first. The whole computation is arithmetic over locally-witnessed events, so it lives in the pure, no-grant `reputation` module (§17) — and a deployment that stores only among devices one person owns can replace it with a constant.

### 13.2 What it buys (the incentive loop)

Reciprocity is spendable as **priority**, which closes the loop without money:
- **Durability for your own data.** Peers you have reliably served accept your `offer`s readily and hold for you; a peer you have never reciprocated with is free to throttle you or ask you to contribute first.
- **A storage allowance proportional to contribution.** A soft, tit-for-tat budget: roughly, the cohort durably holds for you about as much as you have reliably held for others. Leeching is therefore self-limiting, and donating storage is directly valuable to the donor.
- **Preferential read bandwidth and faster repair participation.** Good citizens are chosen first to serve and to repair, and so get more chances to raise their score — the loop compounds.

Honest, available nodes climb; nodes that withhold, lie about capacity, or churn destructively fail verification-fetches, decay, and get routed around (§10). Being a good citizen is the *only* way to get good service for your own data.

**Judging peers you have not dealt with** — a friend-of-a-friend, or a node joining a new sub-cohort — is outside this local picture by design. If a deployment needs *portable, verifiable* reputation that carries across peers who have never stored for each other, it adds the optional signed-receipt and transitive-trust layer of §20. The base system does not need it, and leaving it out is what keeps reciprocity to a page of counters and keeps the §1 promise — Sybil resistance from the shape of the network, not from added machinery.

---

## 14. What to store, and what to evict

A node has finite donated space and will be offered far more than it can hold, so it needs a policy for what to accept and what to drop. This is not a new subsystem — it is the local face of the reciprocity loop (§13). The one structural idea is **two tiers of storage**:

- **Committed** — blocks a node accepted (an `offer` it granted, §18) and now earns standing by reliably serving (§8, §13). These are not dropped casually: shedding one abruptly means failing its next verification-fetch and losing standing. A node sheds a commitment only by **graceful release** — re-placing the block on another peer, or letting repair pick it up — accepting that durability dips until redundancy is restored.
- **Opportunistic cache** — blocks picked up while serving reads, or extra replicas beyond `n`. Free to evict at any time, no commitment, no reciprocity cost.

**Admission (when an `offer` arrives).** Accept weighted by: reciprocity (prefer peers who store for you), social closeness, and how under-replicated the chunk is — a repair offer that lifts a chunk off its low-water mark outranks a routine first placement. Reserve a fraction of quota for commitments so cache cannot crowd out durability, and refuse offers outright when the committed tier is full.

**Eviction (under quota pressure).** Drop cache first, favoring blocks that are cold *and* **verifiably** well-replicated elsewhere — redundancy counted only from holders this node has itself recently verification-fetched (§8), or weighted by the advertiser's standing, never from raw have/want — so a peer cannot spoof abundance with cheap `have`s to make you evict the only real copy. Protect rare or globally under-replicated blocks (the ones repair would struggle to regenerate). Only if still pressed does a node gracefully release its lowest-value commitments — typically those for low-reciprocity peers. Long-unserved orphan blocks — including those of a crypto-shredded file (§11) — are first out the door, which is how dead data is reclaimed without an explicit delete. (If the §25 tombstone layer is enabled, tombstoned blocks are dropped on sight rather than waiting to go cold.)

Concretely, an eviction score like `coldness × redundancy_elsewhere × (1 / reciprocity_with_owner)`, with committed blocks weighted heavily against eviction, captures all of this from signals the node already tracks. The exact weighting is a tuning knob (§28); the property that matters is that a well-behaved node keeps what is scarce and what it owes, and sheds what is abundant and unasked-for.

---

## 15. Threat model and what leaks

Because the network is a closed social cohort, the dominant open-network threats shrink: you only peer with people you've added, so Sybil flooding and eclipse are not the everyday concern they are in an open network, and the admission policy stays restrictive (admitting any author would be remote code execution) so untrusted WASM never lands.

**What is protected.** Content — encryption means holders see only ciphertext (§4.4). The wire — an authenticated, encrypted channel with each frame's signer pinned to the channel identity (the kernel transport's authenticated key exchange and forward-secret record layer, seedkernel §12.6). The content↔holder mapping — there is no global index, and the holder map is never stored, only recomputed live within the cohort. Integrity — content addressing (§4.2) for bulk bytes, and an author signature on the chunk descriptor (§4.3) for the shape metadata that drives repair, so a holder cannot forge it to misdirect healing. Identity — the channel's authenticated key exchange, which pins every frame to a peer key (§2). Enumeration — there is no list-all operation (§5.2); a peer can only confirm ids it is named, and without a file's key its block-ids are unguessable noise (convergent-encryption exception, §24).

**What leaks, accepted by the closed-cohort assumption.** All of these are disclosures *to peers you have chosen to store with, about files you have already shared with them*:
- **Inventory size** — a peer you have/want with learns roughly how much you store and a shared file's block count.
- **Per-file holdings** — to a peer in a file's sharing group, which blocks you hold or want.
- **Chunk shape** — a block's descriptor (§4.3) tells whoever stores it the chunk's sibling block-ids and `(k, m)`, i.e. its size and shape — never its content. The PRF-tag hardening in §23 covers it if a deployment cares.
- **Interest** — asking a key-holder for a file reveals you wanted it (a non-key-holder learns nothing — the id is an opaque hash).
- **Social graph** — who you maintain channels with is visible at the transport level. This is the residual metadata of going social, and it is far smaller than what a global, queryable index would expose. (The optional gossip path of §20, if enabled, widens this — another reason it is off by default.)
- **Ex-member probing** — someone who once held a file's ids can probe for those specific blocks until repair rotates them away; for sensitive files, re-encrypt and rotate on a membership change (expensive, usually done only when it matters).

Optional hardening for cohorts that are less than fully trusted is documented separately in §23; none of it is needed for a friends-or-devices cohort, and adding it by default would make the system the complicated monster we are avoiding.

**Residual kernel-inherited risk.** The kernel does not bound a module's compute beyond the calling guest's execution budget (seedkernel §4.3), so run the heavy `codec` and `reputation` modules under a Worker watchdog (the Tier-2 sandboxed-JS realm reaches them *through* that budget, §2.1). And the storage guest is the grant-richest Part I unit — the one whose realm holds the most logic, behind the one required set (`node`, `fs`, `clock`, the transport's `_net`) — so it is the largest blast radius if a storage unit is ever compromised, the prime audit target, and a standing reason the admission policy (§19) stays a closed allowlist rather than an open author set. Tier-2 confinement (§2.1) bounds that blast radius to its granted services: a compromised guest computes and drives those names, nothing more.

---

## 16. What the kernel gives storage: service grants, primitives, and one shared transport

Storage's confined logic reaches the world through one seam — `host.call(name, bytes)` (seedkernel §12.2) — and the names it relies on are the kernel's own surface, in three kinds: **granted host services** (real I/O or the node's authority, each the shell's own), one **local service id** (`_net`, another bundle's — the transport's — with no privilege of its own), and **ungated names** — the residual `crypto/*` host transforms and the bundle's own module names — which reach nothing a guest could not compute itself and therefore carry no grant at all. Together the granted ones are the whole of Tier 1 (§2.1). They are not storage-specific kernel objects: the runtime side of the seam, the grants-by-service rule, and the claim routing are the kernel's own ([RUNTIME §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)); the table is storage's map onto it.

| Name | Kind | What it gives storage |
| --- | --- | --- |
| `node` | granted service | the node's own things: `node/sign`/`node/verify` under **this slot's one scope** (§16's signing paragraph), `node/identity` (the kernel pubkey the channel pins), and `node/random` — the entropy source, used for content keys (nonces are derived, not drawn, §4.4) |
| `fs` | granted service | the donated blob store (§12): flat app-scoped key → bytes on FS or OPFS/IndexedDB; existence is `size ≥ 0` (no separate `has`), and `fs/stat` provides the backend's used/available for the quota |
| `clock` | granted service | u64 unix ms — liveness, repair jitter, score decay |
| `_net` | local service id — the transport bundle's `services` claim | addressed requests to a cohort peer over its authenticated channel: request/response with a timeout, plus a batched fan-out that reaches many peers in one call (seedkernel §12.10) |
| `crypto/blake2b-256`, `crypto/chacha20poly1305-ietf/{seal,open}` | ungated host transforms | the §4.2 content hash and §4.4 authenticated encryption |
| *bare names* — `codec`, `reputation` | the bundle's own pure-transform modules | ungated for the same reason as the primitives: they are the bundle's own verified bytes (seedkernel §12.2) |

`_net` is the one entry that is not the shell's: it is ordinary claim routing (seedkernel §12.10). The transport is itself a bundle holding the **`link`** capability — the one privileged raw-net seam, granted by the operator's policy (§12.5) — showing a structured service under a local service id the storage guest names in its `requires`. Calling `_net` carries no privilege: a co-resident call from one bundle slot to another, reached through the same claim table that routes a peer's protocol id. Storage adds no backend of its own; `clock` and the entropy source are the deployment's already.

**Crypto is reused, not added.** The transforms storage uses are already in the kernel's residual host table (seedkernel §12.1), and they perform no I/O, so they need **no grant**. **Why a storage-local hash:** block-ids never cross into the kernel — they are pure content addressing within storage (§4.2) — so BLAKE2b-256 remains storage's own choice even though the implementation is already present in core libsodium. Key-sealing is deliberately absent from the guest seam, so the one audited use lives beside the guest in `host/crypto.ts` over that same core instance. Storage therefore ships **no crypto of its own except Reed–Solomon**, and dropping the old MAC-less XChaCha20 stream call lets the shared shell use the smaller core libsodium build.

**The sign/verify pair exists — but it is scoped, and every signed format is tagged.** Storage logic authors its signed objects — the chunk descriptor (§4.3) and the optional tombstone (§25) and file head (§27.3) — through the kernel's scoped pair, never a raw oracle (seedkernel §12.2): `node/sign` signs `DOMAIN_guest ‖ scope ‖ msg` with the scope the slot's own, derived from the admitted bundle's `(author, app)` — never from the caller — and **verification is scoped identically under the same name**, so storage names the verifying key and never reconstructs the prefix. (The raw `crypto/ed25519/verify` primitive stays, ungated like every pure transform — storage never hands it a storage signature.) A storage signature thus verifies only as a storage signature — never as a bundle manifest or a channel handshake, the disjoint members of the kernel's domain family (seedkernel §16.1, §14) — and never as another app's object, while staying portable across the cohort because every node running the same bundle derives the same scope. Checking one still needs only the signer's public key — keyless repair (§9) is untouched. One level down, seed store applies the kernel's sub-separation rule to its own vocabulary: each signed storage format opens with a **distinct leading tag** — one for the descriptor, one for the tombstone, one for the head — so a signed object of one type can never be replayed as another. Signing never ships in storage WASM at all — a module is a pure transform with no grants (seedkernel §4.2); what storage holds is the seam's scoped pair, never key material.

---

## 17. App logic — Tier-2, confined (§2.1)

All storage *logic* is Tier-2: confined, grant-bounded, and reaching I/O only through the §16 surface. It comes in the two confined forms of §2.1 — **WASM** for the pure hot compute, and a **zero-authority sandboxed-JS realm** for the async orchestration. Both are bounded identically: the manifest's signed, human-auditable `guest.requires` (§2.1), no ambient I/O.

| Unit | Form | Grants | Role |
| --- | --- | --- | --- |
| `codec` | WASM module | — (pure) | slice ciphertext into `B`-byte blocks; compute block-ids via `crypto/blake2b-256`; seal/open chunks through ChaCha20-Poly1305 with detached tags in descriptors; seal/unseal content keys client-side (§16); **Reed–Solomon encode/decode (on ciphertext) — the only algorithm in-WASM**; build/parse chunk descriptors |
| `reputation` | WASM module | — (pure) | decayed per-peer reciprocity counters from witnessed verification-fetches and served reads; `reputation.score` query (§13). Swap for the §20 receipts-and-transitive handler when portable reputation is needed |
| **the guest** — `cohort`, `store.coordinator`, `repair` in one realm | sandboxed-JS (zero-authority realm) | `node`, `fs`, `clock`, `_net` — the whole `guest.requires`, one signed list | the peer set and connections; have/want, liveness, and the verification-fetch sampling that backs it (§8); PUT/GET incl. placement negotiation and content-key generation (via `node/random`); windowed transfer; admission, eviction (§14) and reciprocity accounting (§13); the repair loop (§9); and the holder side (admission, sibling rule, content-addressing, quota, store writes) |

The two pure modules (`codec`, `reputation`) hold **no** grants, so the structural sandbox guarantees they can never reach disk or network even if buggy — the Reed–Solomon coding and the trust math are exactly where you want that guarantee. (The residual crypto transforms are ungated, §16, so `codec` keeps its purity.) The orchestration runs in a **sandboxed-JS realm** (§2.1) rather than as wasm because it is inherently async and multi-step — negotiating with peers, streaming blocks, awaiting responses — which the *synchronous* pure-transform module ABI (seedkernel §4) expresses only through awkward correlation-id continuations; the realm lets it stay ordinary async JS while still being confined to the manifest's one required set. Discovery and placement are deliberately light: the guest keeps the peer set and runs have/want, and placement is just negotiation folded into PUT. There is **no separate proof handler** — proving a holder still has data is an ordinary verification-fetch on the existing fetch path, scored locally by `reputation`. Part I needs no replay machinery of its own: every mutator is an awaited request on the pinned, replay-protected channel (§3), and the one state-changing payload — a stored block — is idempotent by content addressing (§4.2). (The mutable head of §27.3, replicated rather than unicast, is the first object that needs a per-signer sequence, and it carries its own.)

> **In the runtime** this table *is* the seed store bundle (seedkernel §12.4): `codec` and `reputation` ship as the manifest's `modules[]` — pure WASM, no grants, reached by bare name through `host.call` — while `cohort`, `store.coordinator`, and `repair` — plus the holder side (admission, sibling rule, content-addressing, quota, store writes) — fold into the bundle's one guest program, confined per §2.1; the reach that guest has is the manifest's signed `guest.requires` (`node`, `fs`, `clock`, `_net`).

---

## 18. Message catalog (the whole control plane: four request/response pairs)

Every storage message is a request/response between two cohort peers on the authenticated channel (§3), and there are exactly four. None carries a signature of its own — the channel pins the sender (§3); the only signed object in the storage protocol is the chunk descriptor riding inside `offer` and `store` (§4.3). (The other signed object of §3, the bundle manifest, is the kernel's own and never a storage message.) All four are **batched**: one message carries many blocks' worth, bounded by a per-transport byte cap (§28), so round trips scale with peers, not blocks.

| Message | Request | Response |
| --- | --- | --- |
| `have` | block-ids the asker wants located (§5) | per-id held / not-held mask (1/0) |
| `offer` | per block headed to this peer: `block_id` + its **signed descriptor** (§6) | per-block **verdict** byte: 1 = accepted, 0 = declined, 2 = quota, 3 = sibling, 4 = descriptor-rejected. Quota (§14) and the sibling rule (§6) are judged over the whole batch. Verdicts > 1 are **advisory diagnostics** — a holder may lie, so the reason is never policy — but they turn the initiator's failure message from a guessing essay into an exact report. |
| `store` | per accepted block: `block_id`, signed descriptor, the bytes (§6 step 4 — the bulk plane's push carrier, §3) | per-block **verdict** byte (same codes as `offer`) — the **binding** admission point: content address (§4.2), sibling rule, and quota are re-checked here, so `offer` stays advisory |
| `fetch` | wanted block-ids (§7; also the §8 verification-fetch) | the blocks, present/absent per id (the bulk plane's pull carrier, §3), each hash-verified by the receiver (§4.2). A block the holder has but its response cap leaves no room for is tagged `UNANSWERED` (2), distinct from a genuine miss (0), so the reader re-requests it. |

PUT and GET are not messages — they are the coordinator's local API, and it speaks only these four to the cohort. Repair adds no message of its own: it runs on `have`, `fetch`, `offer`, and `store` (§9). The optional verifiable-reputation layer (§20) adds `proof.challenge` / `proof.receipt` and `rep.gossip`, and the optional tombstone layer (§25) adds its signed tombstone; the base protocol uses none of them.

---

## 19. Bootstrap additions

On top of the kernel bootstrap, a storage-capable node additionally:

1. Wires the platform backends behind the shell's raw seams (§16) — the flat-key `fs` on a directory (a server) or OPFS/IndexedDB (a browser), the platform's sockets (`link`, consumed by the transport bundle), the clock and the entropy source — none of it storage-specific.
2. Wires an admission policy that admits the storage bundle — restrictive, *never* open, e.g. a content-hash allowlist of the audited bundle plus a closed author set for who may publish upgrades.
3. Admits the signed storage bundle (§2.1, §17): the pure `codec` and `reputation` modules verify and build with it, and the orchestration + holder logic loads into its confined realm with exactly the services the manifest's signed `guest.requires` names. An install loads code and nothing else — authority is the manifest's signature plus the operator's admission decision (§2.1), never anything the code declares.
4. Joins its cohort: connects to known peers (by introduction or a rendezvous point), exchanges have/want, and starts serving.

A node that only wants to *store and serve* runs the holder side (the `fs`-backed store plus the guest's serve path — admission, the sibling rule, `fetch`), adding the repair loop + `codec` only if it will also help heal; it never needs the writer's PUT path. A read-only client needs `codec` plus the GET path. The onion composes per-role.

---

# Part II — Extensions

Everything below is **optional**. The system in Part I is a complete, durable, private store for a cohort of friends or your own devices. Add a layer here only when a specific assumption changes — the cohort grows beyond people who have stored for each other (§20), repair bandwidth dominates cost (§21), throughput on large files matters (§22), the cohort is less than fully trusted (§23), you want cross-user dedup (§24), or you need prompt rather than lazy space reclamation (§25).

## 20. Verifiable reputation: signed receipts and transitive trust

The base reciprocity score (§13) is *subjective* — your private opinion, not something you can show a third party. When a deployment needs **portable, verifiable** reputation — to judge a friend-of-a-friend you have never stored with, or to let a node carry standing into a new sub-cohort — it upgrades the local tally to signed receipts and weights them transitively. This is strictly additive: nothing in §13 changes, and the pure `reputation` module is swapped for a richer (still no-grant) one.

### 20.1 Signed receipts (the earning event)

The earning event is the same verification-fetch that §8 and §13 already perform — request a random block, verify it hashes to `block_id` — but now the challenger emits a **signed receipt** on success:

```
proof.challenge:  { block_id, nonce }                        // challenger → holder (signed)
proof.receipt = signature-wrapped {
  holder_pubkey, block_id, nonce, timestamp, PASS,
}                                                            // signed by the challenger
```

Because a block is small and self-verifying, **the served block *is* the proof of retrievability** — no Merkle path or random-offset sector proof is needed. (Those exist for systems with gigabyte sectors, where you cannot afford to transfer the whole object to check it; at block scale they buy nothing.) A receipt is a third signed storage object of the §3 shape — authority that must travel past the channel it was minted on, since its whole point is being shown to a peer that witnessed nothing. So it is signed through the scoped service under its own leading format tag (§16), and each carries the challenge `nonce` to resist replay. A holder accumulates receipts as a portable track record.

### 20.2 Transitive trust

A peer's reputation is then computed from the receipts *others signed about it*, weighted by **volume & longevity** (passing challenges for more data, over more time), **challenger diversity** (receipts from many *distinct* peers beat many from one), **recency under a hard age bound** `X` (receipts older than `X`, e.g. 90 days, are discarded rather than kept — this decays a peer that stops serving and bounds how much state anyone stores), and **retrieval success** (serving real `fetch`es, not just challenges).

The load-bearing rule: when receipts are gossiped (`rep.gossip`) they **must be weighted transitively, never summed flat**, or a clique manufactures its own diversity by signing each other glowing receipts. Concretely this is **EigenTrust-style transitive trust, personalized to the evaluator**. Each peer normalizes its locally-witnessed scores (§13) into a trust vector, then propagates trust over the gossiped receipt graph by damped power iteration — a peer's transitive score is the fixpoint of

```
trust(P) = (1 − d) · local_seed(P) + d · Σ_c trust(c) · rating_c(P)
```

— restarting from its **own** local view rather than any global pre-trusted set. Anchoring on the local seed is what makes it collusion-resistant and keeps it consistent with the subjective default: trust is computed *relative to you*, so a collective with no edge into your local trust set never gains weight, and there is no global reputation object to agree on or attack. A new honest node starts near zero on the gossip path until someone's local trust reaches it — it proves itself locally first — and because the local seed and every edge obey the recency bound, a peer that stops serving loses both its score *and* its power to vouch for others. The whole computation is arithmetic over collected signed receipts, so it stays in the pure `reputation` module.

**Cost, and why it is optional.** This adds a stored receipt graph and a gossip path, and gossiping who-challenged-whom widens the social-graph disclosure of §15. None of it is needed for a cohort of friends or your own devices, where direct reciprocity (§13) already covers everyone you store with. Add it only when you must trust across people who have never stored for each other.

## 21. Locally Repairable Codes (LRC)

RS (§4.1) is MDS and dead simple — any *k* of *n* reconstruct, repair is a flat `live_blocks ≥ k` count (§8), and the module is tiny. Its cost is **repair amplification**: healing one lost block reads *k* blocks and reconstructs the whole chunk (§9), and the common failure is exactly one lost block per chunk (§6 puts one block per peer). An **LRC** adds per-group *local* parities on top of *global* ones, so a single lost block rebuilds from just its local group — `r ≪ k` reads, a small linear combination, no full-chunk reconstruct (cheaper bandwidth, CPU, and memory, the last of which matters for browser holders, §3).

It preserves everything RS gives seedstore — fixed content-addressed blocks, deterministic re-encode so the signed descriptor (§4.3) still holds, keyless ciphertext repair — unlike a rateless fountain code (RaptorQ), which would break block content-addressing outright. The price is that LRCs are **not MDS**: durability becomes loss-pattern-dependent, so the clean §8/§10 "any *k* of *n*" accounting must become per-local-group health plus a global check, and §6 placement gains a "spread each local group across distinct peers" constraint.

The win scales with *k* — large for cold archives (`RS(20,20)` → painful 20-read repairs), marginal for small hot chunks — so if adopted it likely belongs as a per-chunk option — the same per-file `(k, m)` override is the natural vehicle (§4.1, §28) — rather than a blanket default. Revisit if repair bandwidth turns out to dominate operational cost. (Regenerating/MSR codes cut repair bandwidth further still but contact more helpers per repair — worse coordination under churn — so LRC is the pragmatic step.)

## 22. A dedicated bulk channel

The base bulk plane (§3) carries blocks inside the batched `store`/`fetch` messages — simplest, and entirely inside the kernel transport. For higher throughput on large files, a deployment can run a **dedicated bulk data channel** alongside the control channel on the same connection. The control plane negotiates a transfer (block-ids, order, window) over the §18 messages; raw blocks then stream over the bulk channel as bare frames `[claimed block_id ∥ bytes]` — the claimed id a routing label only: the receiver drops any frame whose claimed id it did not request (unsolicited bulk costs nothing, not even a hash), then verifies `content_hash(bytes) == claimed id` on the rest and drops on mismatch; the hash, never the label, is the authority. This is the most performant option for large files, at the cost of a second channel to manage. The integrity rule is unchanged either way: every block is validated by `content_hash(bytes) == block_id`.

## 23. Hardening a less-trusted cohort

Add only if a deployment's cohort is less than fully trusted; none of this is needed for a friends-or-devices cohort.

- **PRF locator tags.** Address blocks by `tag = PRF_{K_loc}(block_id)` (with `K_loc` a per-file locator key separate from the decryption key) instead of by the raw ciphertext hash. This decouples the locator from the content hash, gives holders and observers unlinkability, and lets you rotate locators on a membership change without re-encrypting. Cost: one extra per-file key and a second identifier in the manifest. **If you adopt this, the chunk descriptor's `block_ids` (§4.3) must be tagged the same way** — they are stable per-chunk identifiers held by every block-holder, so left in the clear they survive as cross-file linkage handles that defeat the unlinkability the tags otherwise buy. Tag them as `PRF_{K_loc}(·)` (the repairer still verifies a regenerated block by recomputing its raw `block_id` locally and re-applying the PRF).
- **Size-hiding have/want.** Pad have-sets to a round number or send them as Bloom filters to blunt the inventory-size leak (§15) — cheap, and the right first step for a semi-trusted pool.
- **Size-Hiding PSI.** A malicious-secure, size-hiding private set intersection would hide set size and non-intersection elements even from an authorized-but-curious peer, at the cost of a multi-message protocol, real per-run latency, mandatory rate-limiting, and a substantial implementation burden. A possible future layer for genuinely semi-trusted community pools, **not** part of this design.

## 24. Convergent encryption for dedup

The base design uses a random per-file key, so two users storing the same file produce different ciphertext and no dedup. A deployment that wants **cross-user dedup** can opt into convergent encryption (key = hash(plaintext)), which makes identical plaintext converge to identical ciphertext and identical block-ids — at the cost of an equality-leak: a holder can tell that two users stored the same content. The leak is in fact larger than that: block-ids become a deterministic function of plaintext, so they are no longer the opaque, unguessable noise §5.2 relies on — anyone with a candidate file can compute its block-ids and probe the cohort (have/want) to **confirm** that a peer holds that exact content. Convergent mode therefore *voids* the §5.2 "can't enumerate, can't probe" guarantee for any guessable or low-entropy file, not just the equality of two stored copies. Off by default; choose it only where the dedup saving outweighs the leak.

## 25. Tombstones: prompt space reclamation

Add only if a deployment wants to reclaim disk *promptly* rather than letting crypto-shredded data age out through eviction (§11, §14); a friends-or-devices store works fine without it.

To get the bytes off disk quickly, the owner publishes a **signed tombstone** for the chunk's block-ids (its signed bytes open with the tombstone's own distinct format tag, §16, so no descriptor or head can be replayed as one), gossiped through the cohort. A holder that receives it verifies the signature, drops the blocks, and stops counting them. Online holders comply at once; offline holders comply when they reconnect and see the tombstone; and the tombstone also tells block-holders to **stop repairing** that chunk, so it is allowed to decay below low-water and be reclaimed instead of healed back to life. Anything a tombstone never reaches still ages out through normal eviction (§14) — the Part I fallback is always underneath.

**Authority.** A tombstone is honored only when signed by the manifest's author (the §2 identity) — the same trust root that signs chunk descriptors (§4.3). For a shared file the simple rule is that only the owner's tombstone removes the data; a member who no longer wants it just drops its own copy and stops repairing — it cannot delete for everyone.

Tombstones are bounded: a holder keeps one only until the referenced blocks are gone and a short grace period passes, so the tombstone set does not grow without limit (retention is a tuning knob, §28).

## 26. Social key recovery via Shamir sharing

Add only for files a deployment wants to survive the loss of the owner's own keys; it trades away part of the §11 deletion guarantee, so it is per-file opt-in and off by default.

Crypto-shredding (§11) cuts both ways: lose the per-file key `K` and *every* sealed copy of it, and the file is gone for good — exactly what you want when deleting, a disaster when you merely lost your keystore. **Shamir's threshold scheme** splits `K` into `n` shares such that any `t` reconstruct it and any `t − 1` reveal *nothing* (information-theoretically). Hand the shares to `n` trusted cohort peers and any `t` of them can later help you rebuild `K` — while no single custodian, and no colluding group smaller than `t`, ever learns it.

**It is the codec's own arithmetic, reused.** Shamir sharing and Reed–Solomon (§4.1) are the same construction — a value placed on a polynomial over GF(2^8), recovered from enough evaluations by Lagrange interpolation. The `codec` already carries that field arithmetic for erasure coding; splitting `K` byte-wise over the same GF(2^8) (one random degree-`t−1` polynomial per key byte) adds no new primitive and no new dependency, and runs in the existing no-grant module. Shares are key-sized, so distribution is a handful of small sealed shares, not a bulk transfer.

**Custody, not read access.** This is distinct from sharing a file (§4.4), which seals `K` to a *reader*. A Shamir share grants nothing on its own; it is held *against future recovery*, not to read the file. Each share is sealed to its custodian's kernel public key (the §4.4 mechanism) so an eavesdropper cannot accumulate shares toward `t`, and each custodian independently decides whether to release — so recovery needs no appointed coordinator, just `t` willing custodians.

**Who a custodian releases to.** The obvious rule — "release only to the file's author (§2)" — is a trap: recovery is invoked precisely when the author's keystore is *lost*, so the requester turns up as a *new* identity that cannot prove it is the author. So while they still hold their keys, the author pre-registers a separate **recovery key** `R` — kept cold and durable, apart from the operational keystore (offline, on paper, in a hardware token, or itself Shamir-split) — and ships its public half in each custodian's share record, author-signed (§2) so the custodian trusts the binding. Recovery is then a request **signed by `R`**, which a custodian verifies against the stored `R` rather than against the lost identity. Because `R` can itself be phished or coerced, a custodian also **announces an incoming request to the owner's other registered contacts and waits out a grace window before releasing**, so the real owner — or the cohort — can veto an impersonation before `t` shares are out; a compromised `R` is retired by re-registering a fresh one (a small signed update). The residual is the social risk the scheme is built on: an attacker who holds `R` — or convincingly impersonates the owner to `t` custodians — *and* survives the veto window can recover, so `t`, the custodian set, and the grace window are sized against how plausibly an adversary could manage that (§28).

**The cost, and why it is opt-in.** Recoverability is the opposite of deletability: if `t` custodians can rebuild `K`, then destroying your own copy no longer crypto-shreds the file — a quorum can resurrect it. A recoverable file is therefore one you have chosen *not* to be able to promptly shred, and true deletion now also means retiring enough shares (or rotating `K`). Choose `t` against both risks at once: high enough that a colluding minority cannot recover, low enough to survive churn among the `n` custodians. For long-lived custody, refresh shares on a membership change (proactive secret sharing) so a slowly-compromised set never accumulates `t` valid shares — a further refinement, unnecessary for short horizons.

---

## 27. Edits and versioning

Add only if a deployment stores *mutable* files rather than write-once blobs; a content-addressed store has no in-place mutation, so an "edit" is never a special operation — it is a re-PUT (§6) that reuses everything that did not change. The base system already gives you this much for free; what this section adds is the handful of rules that make editing *safe* and *efficient*, plus one genuinely new object: a mutable pointer.

**An edit is a new manifest.** A block is named by its hash (§4.2) and a manifest by its hash (§4.3), so nothing in the store can be changed in place: a modified block is simply a *different* block, and a modified file is a *new* manifest with a new `manifest_id`. Deterministic, content-addressed chunking makes this cheap — **every unchanged chunk keeps its exact block-ids**, so the new manifest relists blocks that are already placed, already discoverable via have/want (§5), and already repairing (§9); only the **changed** chunks are re-coded and placed (§6 steps 2–4). Structural sharing across versions thus falls straight out of content addressing, exactly the way it deduplicates identical chunks within one file. An append, or an overwrite of the same length, touches only the trailing or overlapping chunks; the rest of the file costs nothing.

### 27.1 The nonce-reuse hazard (the rule you cannot skip)

§4.4 derives a deterministic nonce from `level ∥ index` under a per-file random `K`. An edit must still never re-encrypt changed bytes under the old `(K, nonce)`: ChaCha20-Poly1305 nonce reuse exposes plaintext relations and invalidates the authenticator's security. Two disciplines honor that:

- **Rotate `K` per version.** Mint a fresh content key and re-encrypt the whole file — exactly the §23 rotation — which folds editing into crypto-shredding: the old version's blocks become permanent noise the moment its key is dropped (§11). The price is that a new `K` changes the ciphertext of *every* chunk, so cross-version reuse is lost (no unchanged-block sharing) and the new `K` must be re-sealed to every reader (§4.4). Right for an occasional wholesale rewrite, wrong for a one-line change to a large file.
- **Version the nonce, keep `K`.** The 12-byte nonce has seven unspent bytes after `level ∥ index`, so changed chunks can draw a fresh nonce while unchanged chunks keep theirs verbatim. One construction derives those bytes from the chunk plaintext, making different plaintext select a different nonce; the derivation bytes ride in the already-signed descriptor (§4.3). Readers keep the same `K`, so distributing an edit is just handing over the new root descriptor. The tradeoff is giving up rotate-to-shred coupling plus a within-key plaintext-equality leak across chunks.

Pick rotation for rare rewrites, versioned nonces for edit-heavy data.

### 27.2 Insert and delete: content-defined chunking

Fixed-size chunking (§4.1) groups the ciphertext by *byte index*, so the blast radius of an edit depends entirely on its shape. **Append** and **same-length overwrite** are local — only the trailing or overlapping chunks change; everything before is untouched and reused. **Insert or delete in the middle is not**: every subsequent byte shifts by the edit's length, so every following chunk's content changes, every following `block_id` changes, and the edit cascades down the entire tail of the file — dedup evaporates exactly where you wanted it. The fix is the one §4.1 already names for cross-file dedup: **content-defined chunking** (Rabin-style boundaries), which re-derives chunk edges from the bytes so an insert or delete perturbs only the chunks around the change and re-aligns the rest. The cost §4.1 notes — variable-length blocks that no longer map one-to-one onto RS shards — is paid by normalizing each content-defined chunk before coding; the signed descriptor and the keyless-repair guarantees (§9) are otherwise unchanged. Adopt CDC only if mid-file insert/delete is common; pure append or fixed-field overwrite does not need it.

### 27.3 The mutable head

Everything above produces a *new* `manifest_id`; nothing yet expresses **"the current version of this file."** The immutable layer deliberately has no mutable name (§4.3), so tracking the latest version is a separate, genuinely new object — a small **signed head** mapping a stable file identity to its current manifest:

```
file head (signed by the owner — the §2 identity):
  tag            // the head's distinct leading format tag (§16)
  file_id        // stable, version-independent name
  manifest_id    // the current version's root
  seq            // monotonic per (signer, file_id)
```

Replay protection is the head's own `seq` — the first per-signer sequence anywhere in the design (§17): the highest `seq` from the file's author wins, and a stale or replayed head is simply dropped. The head is small, signed, and replicated/gossiped through the cohort like any other control message; resolving a file becomes one extra hop (head → `manifest_id`) before the §7 GET. **Single-writer is the whole easy case** — your own files across your own devices, or one owner per file — and it is all this extension covers. **Concurrent multi-writer editing is a different problem** the design does not solve: two heads at the same `seq` are a genuine conflict, and reconciling them needs last-writer-wins, a merge policy, or a CRDT over the manifest — out of scope here, and a reason to keep mutable files single-author unless you are prepared to build that.

### 27.4 History and reclamation

Old versions are not deleted — they are simply **no longer pointed at**. Each prior `manifest_id` stays a complete, immutable snapshot for as long as someone keeps it (and its key) and repairs it, so version history is free and tamper-evident: a manifest *is* its content. When a version is abandoned, the blocks **unique** to it — the changed chunks no later version relists — stop being repaired, go cold, and age out as orphans under ordinary eviction (§14); blocks still shared with a live version keep their redundancy because a current manifest still names them. Prompt reclamation of a superseded version uses the existing toolkit: drop the old key to crypto-shred it (§11), or publish a tombstone (§25) for the blocks no surviving version references. Pinning a specific version — a published release, a signed checkpoint — is just keeping that `manifest_id` and refusing to let it be evicted, the §14 "protect rare blocks" lever applied deliberately.

**The cost, and why it is optional.** Write-once data — content-addressed blobs, immutable media, backup snapshots — needs none of this: it already has everything in "an edit is a new manifest" and never resolves a head. Mutable files cost a nonce discipline (§27.1) you must not get wrong, optionally content-defined chunking (§27.2), and a new signed pointer (§27.3) with the usual single-writer-vs-concurrent tax. Add it only when files genuinely change in place from the user's point of view; the rest of the system never learns that a `manifest_id` had a predecessor.

---

## 28. Tuning knobs and open questions

- **`(k, m)`, chunk size, and block size `B`** — the durability/overhead dial, set once per deployment (§4.1). Size `(k, m)` against measured cohort churn so the chance of losing more than *m* holders within one repair interval is acceptably small; a per-file override is an extension, not core. `B` sets how many blocks a file becomes, and therefore manifest and have/want size: larger blocks shrink the manifest but cost more per verification-fetch and more holder memory, so keep `B` small enough that re-fetching a whole block stays cheap — which is what lets proof-of-retrievability skip Merkle paths (§8, §20). A few tens to a few hundred KB is typical; no protocol constant bounds it (§3).
- **`maxMessageBytes`** — the per-node cap on one batched message (§3, §18). Operator policy, not protocol: floor set by the transport (a WebRTC data channel reassembles far less than a TCP link), ceiling by how much a node — especially a browser — can hold at once. Peers may disagree on it; a mismatch degrades to extra round trips, never a failure.
- **Grace window `G` and liveness cadence** — set so ordinary offline patterns (overnight, commute, reboot) never trigger repair, but real departures do within a bounded time. Too short → churn storms; too long → slow healing. Includes how often, and how widely, to sample verification-fetches (§8).
- **Repair jitter** — trades healing speed against repair traffic and duplicate-repair avoidance. (The low-water mark itself is *not* a separate knob: it is `⌈m/2⌉` of the margin the chunk's own descriptor signs, §8/§9, so it moves with `(k, m)` and cannot be set out of step with the geometry it guards.)
- **Cohort uptime** — the load-bearing durability decision (§9): each chunk's holders should include at least one well-connected, long-lived peer so repair can always run.
- **Reciprocity decay & weighting** — the half-life of the local score and how strongly to net give-against-take (§13).
- **Committed/cache split & eviction weights** — how much quota a node reserves for durable commitments vs. opportunistic cache, and the weighting of the eviction score (§14).
- **Tombstone retention** (if the §25 tombstone layer is enabled) — how long a holder keeps a tombstone after the referenced blocks are gone.
- **Extensions, if enabled** — verifiable-reputation window `X`, EigenTrust damping `d`, and local-seed anchoring (§20); RS vs. LRC and where, and per-file `(k, m)` overrides (§21); in-band vs. dedicated bulk channel (§22); hardening choices (§23); convergent vs. random-key encryption (§24); prompt tombstone reclamation (§25); Shamir key recovery and its quorum `t` (§26); the edit nonce strategy (key-rotation vs. versioned-nonce), fixed vs. content-defined chunking, and single- vs. multi-writer heads (§27). All are off or RS/in-band/deployment-default by default.

Everything above is expressible as modules, one confined guest, two signed objects, and a restrictive admission policy — i.e. as one ordinary seedkernel bundle. The kernel never learns what a "file" is; it just keeps routing the protocol id to the slot's guest while the channel pins who is speaking, the bulk bytes never enter its dispatch path, and the core stays five ideas deep: a social cohort, encryption, content addressing, erasure coding, and have/want — with reciprocity, not a coin, rewarding the good citizens.
