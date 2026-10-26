# seedstore: specification

## 1. Introduction

This is the design spec. For an overview and a quick start, see the [README](../README.md). For the implementation of Part I, and where it departs from this spec, see [WASM/README.md](../WASM/README.md).

Seedkernel routes a wire protocol id to one bundle's confined guest over an encrypted, authenticated channel. It has no notion of a file, and nowhere for a multi-megabyte one to live. Seedstore is that store, built only from pieces seedkernel already provides: a channel that pins who is speaking, a protocol id to dispatch on, and a signed bundle that carries the code and its authority. Bulk bytes live beside the dispatch path, referenced by content hash (§3).

**Goals.** A node donates whatever storage it has and stores files across its peers such that:

- no single peer can make a file unavailable (§10);
- peers can be offline for stretches without data loss (§8);
- the system heals itself when redundancy drops (§9);
- file size is bounded only by the cohort, not by any message or object size (§4.3);
- good citizens earn durability for their own data through direct reciprocity, not a coin (§13).

**The assumption.** The network is **closed and social**. You store with peers you have a relationship with (friends, friends-of-friends, or an explicit storage group), not in an open market of strangers. That assumption keeps the design small: privacy and Sybil resistance come from the *shape* of the network, not from added cryptographic machinery. The whole system is five ideas: **a social cohort, client-side encryption, content addressing, erasure coding, and a have/want exchange**.

**Design principles:**

- **No new host concepts.** Storage is one signed bundle (pure-transform WASM modules plus a confined guest) and six request/response messages (§18), gated by the channel that already pins every peer and the policy that already admits every bundle.
- **Integrity comes from content addressing, not signatures.** A block either hashes to its name or is discarded, so bulk transfer needs no per-message verification (§3).
- **Identity comes from the channel.** A peer *is* the node public key its authenticated channel pinned (§2). Nothing is signed to establish it.
- **Redundancy is erasure coding, not replication.** Any *k* of *n* blocks reconstruct a chunk (§4.1).
- **Placement is by relationship, not global address.** Blocks live on cohort peers chosen by negotiation, and who holds what is discovered live. There is no global index, by design (§5).
- **Confidentiality is structural.** The wire is encrypted, stored data is encrypted so holders see only ciphertext (§4.4), and no directory maps content to holders.
- **Trust is local before it is global.** Direct, pairwise reciprocity (§13) is the baseline. Portable reputation is an optional layer (§20).
- **The trusted base is small and separate from the logic.** Only the host's I/O backends are trusted. All storage logic is confined and upgradeable (§2.1).
- **Browser nodes and long-running peers run the same protocol.** They differ only in their `store` backend and default quota (§12).

---

## 1.1 Concepts at a glance

- **Block**: the one unit of stored data, a `B`-byte slice of ciphertext named by its hash: `block_id = block_hash(author_pk, block_bytes)` (§4.2). A block is both an erasure-coding shard *and* the unit that moves on the wire. `B` is a deployment knob (§28), kept small so a whole block re-fetches cheaply (§8); no protocol constant bounds it (§3).
- **Chunk**: a slice of a file, up to `k` data blocks plus `m` Reed–Solomon parity blocks, `n = k + m` blocks in all, any *k* of which reconstruct it (§4.1). `(k, m)` is a deployment-wide setting; a short final chunk codes at a smaller `k` of its own.
- **Chunk descriptor**: the small record of a chunk's shape (geometry, authentication tag, and its `n` block-ids), signed by the file's author. It is all a repairer needs, and it is stored alongside every block of the chunk (§4.3).
- **Root**: what a reader is handed: one signed descriptor plus the content key `K` (§4.4). A file too big for one chunk has an *index*, which is just the list of its descriptors, chunked and placed like any other bytes; the root is the descriptor at the top of that index (§4.3). Neither the root nor the index names holders.
- **Cohort**: the bounded set of peers you have a storage relationship with. Discovery, placement and repair all happen inside it. There is no global overlay.
- **Have/want**: the discovery primitive. Peers tell each other which block-ids they hold or want, in one round trip, with no crypto protocol (§5).
- **`store`**: storage's facade over the host's flat-key `fs` service (§16): a directory on a server, OPFS/IndexedDB in a browser (§12).

```
file ─encrypt─► ciphertext ─slice into k─► data blocks ─RS(k,m)─► n blocks (k data + m parity)
                                                                   │ each block = one content-addressed ciphertext block
                                                                   ▼
                              placement: negotiate with cohort peers (offer / accept, §18)
                                                                   ▼
                    push block + chunk descriptor ──► distinct cohort peers      locate later via have/want
```

---

# Part I: The minimal system

This is the whole system you need: a durable, private, self-healing store for a cohort of friends or your own devices. It is complete on its own. Every section in Part II is an optional add-on for when a specific assumption changes.

## 2. How it composes with seedkernel

Storage changes nothing in seedkernel. It is one signed bundle on a generic host, and it relies on three things the host provides. How each works is seedkernel's to document ([RUNTIME §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)); this section says what storage needs of it.

**The channel is the identity.** Seedkernel's transport gives every pair of peers an authenticated, encrypted channel, whatever carries it ([RUNTIME §12.6](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md), [CHANNEL](https://github.com/arj03/seedkernel/blob/main/docs/CHANNEL.md)). A peer *is* the node public key its channel pinned. Every operation that needs "who" (who is offering, who is fetching, whose reciprocity standing moves) reads it off the channel rather than out of a signature, so there is no per-message signing and no account system. Storage reaches its peers through the transport's `_net` service under its own signed `protocols` id, so a frame for that id reaches the storage guest and no other (§16). The control plane is typed request/response on that channel (§18). Bulk blocks ride the same messages as hash-verified payloads (§3); a dedicated bulk channel is an optional upgrade (§22).

**The bundle carries the code and its authority.** Storage arrives as one author-signed bundle ([RUNTIME §12.4](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)), and that signature authenticates storage's code to a node that received it through any number of relays. The bundle holds two pure WASM modules with no grants, `codec` (Reed–Solomon) and `reputation`, plus the confined guest, whose whole reach is the signed `guest.requires` list: `node`, `fs`, `timer` and `_net` (§16). The timer is how a repair a node agreed to runs after the request that asked for it (§9). Which authors may install it is the operator's admission policy ([RUNTIME §12.5](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)).

**Crypto is the host's.** Hashing and authenticated encryption use the host's `crypto/*` transforms, and signing uses its scoped `node/sign` (§16). The only algorithm storage ships in WASM is Reed–Solomon, which libsodium lacks. Confidentiality at rest, which a hop-by-hop channel does not give, is added client-side (§4.4).

What the host does not give storage is anywhere for the bytes themselves to live: a module is a pure transform, and the channel moves opaque frames. Bulk data therefore lives beside the dispatch path, referenced by hash (§3).

---

## 2.1 Trust model: three tiers

Running a seedstore node extends your trusted computing base (TCB), but the part you *must* trust is small and separate from the part that changes. Smallest TCB first:

**Tier 0: the host.** Seedkernel itself, which admits code under an admission policy and confines it. The root of trust.

**Tier 1: the I/O base (trusted).** The host services storage is granted (`fs`, `node`'s scoped sign/verify, and the network through the transport bundle) and the host's `crypto/*` transforms. They are the only code that performs real I/O, and they are seedkernel's, not storage's. This is the *whole* of what seedstore adds to your TCB.

**Tier 2: the logic (confined, upgradeable).** Everything storage ships: `codec`, `reputation`, and the guest (§17). It reaches I/O only through the Tier-1 services its signed manifest names. An upgrade (the same author's bundle at a higher version, seedkernel §12.4) runs in the same sandbox, and a wider grant is a visible change to the signed manifest, never a silent acquisition. It takes two forms:

- **WASM** for the pure, hot compute (`codec`, `reputation`), which holds no grants at all.
- **A zero-authority JS realm** for the orchestration (cohort, coordinator, repair) and the holder side (admission, the sibling rule, content addressing, quota, store writes), which are async and multi-step. Both roles share one realm and its one entrypoint, which runs one invocation at a time ([RUNTIME §12.3](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)).

The line that matters: **"trusting seedstore" means trusting Tier 1 (small, stable, the host's), not Tier 2 (large, churning, upgradeable).** A buggy or compromised Tier-2 unit can only compute and call the services it was granted. A node *is* the generic host plus this bundle; the [WASM implementation README](../WASM/README.md) says how to run one.

---

## 3. The two planes: control and bulk

The host gives bulk bytes nowhere to live (§2), so they live beside the dispatch path, referenced by hash. The two halves are also worth separating because **they authenticate differently.**

**Control plane: small peer-to-peer messages.** Have/want, placement offers, and fetch requests (§18). These ride the seedkernel transport's authenticated channel and need **no per-message signature**: the channel pins the remote's node identity and encrypts, integrity-protects and replay-protects every frame (seedkernel §12.6), so the channel is the sender authentication.

Only what must outlive a channel, or carry authority beyond it, is *signed*. In Part I that is exactly **two objects**:

- **The bundle manifest** (seedkernel §12.4): storage's own code, authenticated to a node that may have received it through any number of relays, where no channel can speak for the author.
- **The chunk descriptor** (§4.3), riding inside placement messages. It is signed by the file's *author*, not the message's sender, because a repairer must trust a chunk's shape without ever having spoken to that author, and the peer handing it over is exactly the party who would benefit from forging it.

Both are authority that has to survive the hop it arrived on. The optional tombstone (§25), file head (§27.3) and reputation receipt (§20.1) are more of the same, when a deployment enables them.

**Bulk plane: content-addressed blocks.** Blocks are **self-verifying by hash**, so they need no signature for integrity. In the base design they ride *inside* the channel's messages, in the push half of `store` and the reply half of `fetch` (§18), as unsigned, hash-named bytes. The receiver checks `block_hash(author_pk, bytes) == block_id` against an id it asked for or admitted, and drops the block on mismatch: the hash, never the framing, is the authority. This stays inside the seedkernel transport, inherits the channel's encryption and key pinning, and costs no signature verification per block. (A dedicated bulk channel with raw framing, for higher throughput on large files, is an optional upgrade, §22.)

The rule: **the control plane carries hashes and authorization; the bulk plane carries hash-named bytes that authenticate themselves.**

**No protocol constant bounds either plane.** Transfers are batched and windowed: one message carries many blocks, every message stays under a **per-transport byte cap**, and a peer keeps only a bounded window of messages in flight (§18, §28), so round trips scale with peers rather than blocks. That cap (`maxMessageBytes`) is **operator policy, not protocol**. It is a per-node number, so a cohort may disagree on it: a holder bounds each `fetch` response by *its* cap, and a client with a larger cap pays a few extra tail requests rather than failing (§18). Its floor comes from the transport (a WebRTC data channel reassembles only tens of KB; the host's own frame cap is 2 MiB, seedkernel §16.1) and its ceiling from memory, because a browser node must never hold more than a window of a large file at once.

---

## 4. Data model: files → chunks → blocks (and an index of the same)

### 4.1 Chunking and erasure coding (the redundancy primitive)

A file is encrypted (§4.4) and the ciphertext is cut into **blocks** of `B` bytes. Blocks are grouped into **chunks** of `k`, and each chunk is **Reed–Solomon `RS(k, m)`** encoded into `m` more **parity blocks**: `n = k + m` blocks per chunk, any *k* of which reconstruct it. Every block, data or parity, is the same size and the same kind of object.

`B` is a deployment knob (§28), not a protocol constant: no wire constant bounds a block (§3), and the only pressure is to keep it small enough that a verification-fetch transfers a whole block cheaply (§8).

**Defaults:** `k = 2, m = 2`, so `n = 4`: 2× storage overhead, surviving the loss of any 2 of a chunk's 4 holders. It needs only 4 distinct holders per chunk, which a small cohort of devices or friends can supply. Naïve 3× replication survives the same 2 losses at 1.5× the cost. A cohort with at least 16 well-connected peers can run `RS(10, 6)` instead: 1.6× overhead, surviving any 6 of a chunk's 16 holders. The code is **systematic** (the *k* data blocks are the ciphertext verbatim), so when all *k* data blocks are present a read just concatenates them; the GF(2⁸) decode runs only to heal around missing blocks. Encode and decode are self-contained byte arithmetic in a small no-grant WASM module, and they operate on ciphertext (§4.4), so reconstructing a missing block never needs the file's key.

**Geometry is deployment-wide, but self-described.** `(k, m)` is one value the whole store agrees on, yet each chunk descriptor records its own `(k, m, B)` under the author's signature (§4.3). So a repairer (§9) needs no deployment config to audit and rebuild a chunk, a reader decodes by the same numbers the writer used, a cohort can run mixed geometry, and a holder cannot alter the geometry without breaking the signature. Per-file durability (cold archives at `RS(20, 20)`, hot ephemeral data at `RS(4, 2)`) is a deployment refinement, not part of the core (§28).

**The RS construction is pinned with `(k, m)`.** `(k, m)` fixes the code but not the bytes, and keyless repair (§9) holds only if every peer's encoder emits byte-identical parity. So the field polynomial, generator matrix and column order are fixed too: systematic RS over `GF(2⁸)`, primitive polynomial `0x11D`, a Cauchy matrix in fixed column order.

**A block is a shard is the unit on the wire.** Because a chunk is exactly `k` blocks, there is no separate "fragment" object to slice, list or address: a chunk's descriptor is simply its list of `n` block-ids, and one block per message slot is true by construction. (Fixed-size chunking is the simplest choice. Content-defined chunking would allow cross-file dedup at the cost of variable-length blocks that no longer map one-to-one onto shards; §27.2.)

**Every chunk is coded at its own `k`.** A chunk carries `kc = max(1, ceil(plaintext / B))` data blocks (at most the deployment's `k`) and is `RS(kc, m)` encoded, so a short chunk is never padded out to the full `k`.

- At `kc ≥ 2` this produces `kc + m` distinct blocks.
- At `kc = 1`, `RS(1, m)` degenerates: every parity block is byte-identical to the lone data block. The codec is skipped and the one block is placed on `m + 1` distinct peers instead.

**Coded and replicated chunks have one shape.** Every descriptor lists exactly `n = k + m` ids. A `k = 1` chunk lists its lone block `m + 1` times, so **multiplicity carries the replica count**:

```
coded (k ≥ 2)   block_ids = [b₀ … b_{k-1}, p₀ … p_{m-1}]   n = k+m distinct ids, one holder each
k = 1           block_ids = [b₀, b₀, … b₀]                  n = k+m listings of one id, m+1 holders
```

There is nothing to branch on. Each listed id is a placement slot on its own distinct peer, a read takes any `k` **distinct** listed blocks, and the health of either shape is one number, the loss margin `Σ min(live_holders, multiplicity) − k` (§8). The `min` stops an over-replicated block from inflating the margin past what its author asked for. Replication at `k > 1` does not exist, since `RS(d, m)` strictly dominates it for all `d ≥ 2`. (At `m = 0` the two shapes coincide: no parity and no second copy are the same zero-redundancy chunk.)

The one rule this shape needs: a holder **declines a block it already holds**. A repeated id's `m + 1` slots must be `m + 1` different peers, and quietly accepting a second copy would burn a slot without adding a holder.

### 4.2 Blocks are content-addressed

Each block is named by a hash over its author and its bytes:

```
block_hash(author_pk, bytes) = BLAKE2b-256(ASCII("seedstore:block\0") ∥ author_pk[32] ∥ bytes)
```

Content addressing makes every block **self-verifying**: a receiver recomputes the hash and rejects anything that doesn't match, so a malicious holder cannot return corrupt bytes undetected, and bulk data needs no signature (§3). Because the bytes are ciphertext (§4.4), a `block_id` is opaque and unguessable to anyone who has not handled that exact file.

**Why the author is in the hash.** The author key is taken from the signed descriptor that carries the block (§4.3). The zero byte terminates the domain string and the key is a fixed 32 bytes, so the fields cannot be slid past one another. If the id covered the bytes alone, a cohort peer could re-sign another author's ciphertext under its own key, keep every id intact, and substitute its own sibling list and geometry: the signature would verify, the ids would match, and the chunk would be quietly re-parented. With the author in the hash, re-signing produces different ids, so the impostor forfeits the blocks. Being a known peer (§5.1) buys admission eligibility, never ownership of another peer's blocks. Holders, readers and repairers all recompute the id from the author's *public* key alone, so keyless repair (§9) is untouched.

### 4.3 The signed chunk descriptor (and the index built from it)

**One** small object describes a file: the per-chunk **descriptor**. A file's index is an ordered list of these, stored the same way the file body is.

The descriptor is a chunk's *shape*, and it is all a *repairer* needs (§9). *Reading* a file needs the whole index and the content key, and is limited to the sharing group. *Repairing* needs much less, and should be possible for far more peers, so every stored block carries its chunk's descriptor.

The descriptor **must be authenticated**. `block_id` covers a block's bytes but says nothing about the relationships between blocks, so a malicious holder could alter an unsigned descriptor to misdirect or suppress repair: point a repairer at blocks that don't exist, or hide that a chunk is decaying. The descriptor is therefore **signed by the file's author** (the §2 identity):

```
descriptor D:
  tag                  // leading format tag, distinct per signed storage format (§16)
  level                // 0 = the file's own ciphertext; ℓ > 0 = an index chunk over level ℓ−1
                       //   (below). Also the §4.4 nonce domain.
  k, m, B              // this chunk's own geometry (§4.1), so a repairer needs no deployment
                       //   config and readers never disagree with writers
  tail_bytes           // how many of the chunk's k×B plaintext bytes are real; the rest is
                       //   zero padding. A reader trims each chunk by its own signed number.
  group                // the group the author placed the file in (§5.1), 1–32 ASCII characters;
                       //   every holder reads it against its own roster
  auth_tag             // the chunk's detached ChaCha20-Poly1305 tag (§4.4)
  block_ids[0..n)      // ALWAYS n = k + m. Coded: 0..k data, k..n parity, one per peer.
                       //   k = 1: the same id listed m+1 times, one per peer (§4.1).
signed by the file's author
```

**Admission checks.** Before accepting a block, a peer verifies three things about its descriptor:

1. The author's signature is valid, over the scoped, tag-led preimage of §16.
2. **The signing key, and the peer placing the block, are members of the group the descriptor names, in the holder's own roster** (§5.1).
3. The block's own `block_id` is in `block_ids`.

The second check is what makes the first mean anything. The envelope carries the author's public key inside itself, so a signature checked against that key alone proves only that somebody held *some* private key: any cohort peer could mint a fresh keypair, self-sign a descriptor with a truncated sibling list, and concentrate a chunk on itself. Anchoring the author to a group member costs nothing and makes a forgery **attributable**, which is reciprocity's job (§13). The price is that a group is mutual: a writer must be in its holders' rosters under the group it names, and a peer dropped from the roster can no longer have its files repaired.

A block that fails any check is rejected. The descriptor is therefore **mandatory on every placement message** (§18). Otherwise any cohort peer could put arbitrary bytes on a holder while sidestepping these checks and the sibling rule (§6). The descriptor's signed `B` is also what a holder charges against its quota (§14).

The result: a holder cannot alter the descriptor it serves (the signature won't verify), nor re-sign it under its own key while keeping the block-ids (each id binds the ciphertext to its author, §4.2). These checks need only the author's *public* key, so keyless repair (§9) is preserved, and a repairer re-certifies its output against the signed `block_id`s, so even a bad descriptor cannot mint garbage (§9). The descriptor discloses a chunk's size and shape to anyone storing a piece of it (accepted in §15), but never its contents.

**The index.** A chunk's plaintext is either file bytes or a list of descriptors. A descriptor list is self-delimiting and headerless:

```
[ len u32 ‖ descriptor ] …
```

It needs no version (each descriptor's tag is its version), no file size (each descriptor signs its `tail_bytes`), and no algorithm field (the format fixes it). The list is placed by **exactly the call that placed the file body**: same `B`, same `(k, m)`, same windowing, placement, admission and repair. If it came to more than one chunk, the descriptors *those* produced are placed the same way, until a single descriptor is left: the file's **root**, which is what a reader is handed alongside `K` (§4.4). A file that fits in one chunk has no index at all (its own descriptor *is* the root), and a reader tells the cases apart by the signed `level`.

**The index is shallow.** One chunk holds thousands of descriptors, so the loop runs zero times for a small file, once for almost everything else, and never a third time below petabyte scale. At `RS(2,2)` an index entry is 257 B (a 4-byte length plus a 253-byte descriptor), so a 512 KiB chunk holds 2040 of them:

| `level` of the root | covers, at `k=2, m=2, B=256 KiB` |
|---|---|
| 0: the root is the file's only chunk | up to 512 KiB |
| 1: one list of descriptors | up to ~1.07 GB |
| 2 | up to ~2.2 TB |
| 3 | up to ~4.5 PB |

The one thing this asks of a deployment is that a chunk can hold **two** descriptors (`k × B ≥ 2 ×` the entry size), a property of `(k, m, B)` alone, so it is checked once when a PUT opens, never discovered mid-placement. Realistic geometries clear it by orders of magnitude.

**What this costs and buys.** The cost is that a reader is handed a variable-length signed descriptor (a few hundred bytes) rather than a 32-byte hash. In return a file's body and its index are the same kind of object, placed, repaired and encrypted by the same code, and there is **no size ceiling**: every block on the wire is exactly `B` bytes at any file size. (A flat, single-level list would cap a file at ~1.07 GB at the geometry above, and far lower on a WebRTC node's message cap.)

The index says *what* blocks a file is made of, never *which* peers hold them. That is discovered live via have/want (§5), so the holder map stays current under churn and repair instead of going stale.

**No position, two homes.** The descriptor carries no chunk index: a chunk's position is its order in the index level that lists it, and a repairer never needs it, only the sibling block-ids and the chunk's geometry. The same descriptor lives in **two places**: inside the encrypted index, so a reader gets every chunk's shape at once; and in the clear beside each stored block, so a repairer without the index can still verify the chunk's shape from the author's public key. The signature is checked in both roles: a holder checks it at *admission*, where storage authority is granted, and a reader checks it on the *root*, the one descriptor with no authenticated parent (§7). Every descriptor below the root is reached through content-addressed ids and needs no second check.

### 4.4 Encryption (the load-bearing privacy mechanism)

The seedkernel channel encrypts each link hop by hop, but nothing it carries stays confidential once written to a holder's disk. **Encryption is what makes the closed network safe**: it lets you store on cohort peers who can read nothing, and it makes block-ids opaque. Seedstore encrypts **client-side, before erasure coding**, through the host's ChaCha20-Poly1305 transform (§2, §16):

- **Per-file key, derived nonces.** Generate a random **content key** `K` per file. Seal each padded chunk under `K` with ChaCha20-Poly1305-IETF and a deterministic 12-byte nonce containing `level ∥ index`: the chunk's signed index level (§4.3) and its position within that level. A fresh `K` per file makes the nonce namespace unique, and within one file `(level, index)` never repeats; the level byte separates an index chunk from a body chunk at the same position. Index levels are encrypted under `K` the same way.
- **Detached tag.** Split each sealed chunk into same-length ciphertext plus its 16-byte tag. Only the ciphertext is sliced and erasure-coded; the tag travels in the signed descriptor (§4.3). So every stored block stays exactly `B` bytes, and the systematic data blocks are the ciphertext verbatim.
- **Sharing a file is sharing the key, not moving bytes.** The owner sends a recipient `{ root_descriptor, seal(K → recipient_pubkey) }` over the authenticated channel, with `K` sealed to the recipient's node key (libsodium `crypto_box_seal`, converting the Ed25519 node key to X25519). `K` is never stored in clear on holders, which avoids the circularity of putting `K` inside an index that `K` encrypts. Re-sharing is one more sealed copy. Revocation that must deny future reads rotates `K` and re-encrypts (§23).
- **No accidental dedup.** Random per-file keys mean two files never produce colliding ciphertext, so a `block_id` means something only to someone who has handled that exact file. Convergent encryption (key = hash(plaintext)) is an opt-in for deployments that want cross-user dedup and accept its equality leak (§24).

**Why the tag is detached.** Content addressing already rejects a modified block before decryption, since every block must hash to an author-signed `block_id` (§4.2–§4.3). The AEAD tag adds an independent keyed check, including clean rejection of a wrong content key. Keeping it in the descriptor rather than appended to the ciphertext preserves the invariant that every shard is exactly `B` bytes, and repair stays keyless because it copies the signed tag without verifying it under `K`.

**Post-quantum note: the sealed key is the harvest-now artifact.** `crypto_box_seal` is X25519 confidentiality, so whoever records a sealed `K` today can open it once a quantum computer breaks the DH problem. Unlike the channel (seedkernel §14.1), nothing re-encrypts a sealed `K`: it is durable by design, kept in keystores for as long as the share lasts. The exposure is bounded by what a holder keeps, and the fix fits the design: **re-sharing is one more sealed copy, so a PQ migration is a bulk re-share**, one fresh seal per recipient per file, with nothing else changing. What a PQ seal still lacks is a recipient ML-KEM public key: ML-KEM is packaged in the transport bundle, but a recipient's KEM key has no address, published key or share field yet. Until it does, holding sealed keys past a multi-year sensitivity horizon is a deliberate choice: rotate `K` (§23) and re-seal, or accept the clock.

---

## 5. Discovery: a social cohort with have/want

Two questions need answers (*which peers should hold a block?* and *who holds it now?*) without a public, queryable index mapping content to holders. The closed-network assumption (§1) answers both with almost no machinery.

### 5.1 The cohort

A node keeps connections to a **bounded set of peers it has a relationship with**: direct contacts plus, optionally, a hop or two out. There is no global index or routing table, and nothing about who holds what exists outside your cohort. New peers join the way Scuttlebutt peers do, by introduction or through a rendezvous point. Cohorts are tens to low hundreds of peers, which keeps every operation here cheap.

**The cohort is a roster of named groups**, kept by each node: say `mine` for one person's devices and `friends` for a circle of friends, each a list of member keys. The cohort is every member of every group, and nobody else: an authenticated link alone admits nothing, and a node answers no request from a peer outside its roster. The roster is dynamic. Whatever keeps it, the operator or a separate groups app, replaces it whole at any time, and the next request is judged by the new one. Who may link at all stays the transport's own setting.

- **A file lives in one group.** A PUT names the group, the descriptor signs its name (§4.3), and its blocks are placed on that group's members only. A holder stores a chunk only if it lists both the author and the placer under that name.
- **Goodwill is per group** (§13). Standing a peer earns by serving one group's chunks counts in that group and no other, and so does the allowance it buys (§13.2). Being a reliable friend earns nothing among someone's own devices, and the reverse.
- **Names are local.** Each node keeps its own member list per name, so `friends` means whoever this node lists as friends. Two nodes cooperate on a group when each lists the other under the same name.

### 5.2 Have/want is the whole discovery layer

- *Who currently holds block B?* Ask the cohort. A have/want carrying the block-ids turns up whoever has them right now. Nothing is pinned in advance, so the answer is always current.
- *Are there extra replicas, and does a given peer still hold its blocks?* The same one-round exchange: "I want these `block_id`s" / "I have these `block_id`s". No lookup walk, no cryptographic protocol, no rate-limit machinery.

A have/want only ever **names ids the asker already knows** (ids it holds, or was handed in a descriptor), and the reply confirms or denies exactly those. There is no "list everything you have" message anywhere in the protocol, so files cannot be enumerated: *don't share = can't probe*.

Block-ids are hashes of random-key ciphertext (§4.4), so to a peer outside a file's sharing group they are opaque noise, and on the wire they are encrypted. Only those who already hold the file's key, the people you deliberately shared with, can interpret a have/want entry.

Have/want is **advertisement, not proof**: a peer can answer "have" for a block it cannot serve. §8 closes that gap with verification-fetches.

### 5.3 What this is, and is not

This is deliberately **not an open market**: strangers cannot find or serve your data, because there is no global index and nothing to query. That absence is the privacy property we want, and the cost is that storage is confined to your cohort.

What leaks, and why it is acceptable: a peer you exchange have/want with learns which block-ids you hold or want *of files you already shared with it*, and roughly your inventory size. These are disclosures to people you chose to store with, about files you shared with them. The full list, and optional hardening for less-trusted cohorts, are in §15 and §23.

---

## 6. Writing a file (PUT)

1. **Encrypt.** The owner generates a random content key `K` (via `crypto/random`, §16) and seals the file chunk by chunk under `K` (§4.4).
2. **Erasure-code and describe.** The `codec` turns each chunk's *k* data blocks into *m* parity blocks. The owner computes all `n` block-ids (§4.2), forms the chunk's descriptor, and signs it (§4.3). A chunk of a single block skips the codec and lists its block `m + 1` times instead (§4.1).
3. **Place by negotiation.** For each block, the coordinator picks candidate cohort peers, ordered by reciprocity standing (§13) and current reachability, and sends an `offer`: the block_id plus the signed descriptor (§18). The block's size is the descriptor's signed `B`, never a separate field a sender could disagree with. A peer with free quota and willingness accepts; a decline moves the coordinator to the next candidate. There is no global placement function, just a short private negotiation within the cohort.
4. **Push.** On accept, the coordinator sends the block with its signed descriptor (§3), so the holder can verify it and later help heal the chunk.
5. **Place the descriptors too.** The signed descriptors, in order, are themselves bytes: run them through steps 1–4 unchanged, and repeat until one descriptor is left (§4.3). Usually this happens once. Descriptors list block-ids, not holders, so placement can shift under repair without anything going stale.
6. **Publish.** The **root descriptor** is what the owner keeps and shares, with `K` sealed to each recipient (§4.4) and sent over the authenticated channel. The share needs no signature of its own: the channel pins who sent it (§3), and the seal keeps `K` secret.

**Distinct holders.** The `n` blocks of a chunk go to **distinct peers**, so losing one peer costs at most one block of any chunk: the core of the §10 invariant. The coordinator places this way, and each holder also enforces it: because every `offer` carries the descriptor, a holder declines a block of a chunk it already holds a sibling of, **including a repeat of the same block** (§4.1). So the invariant survives a careless or malicious placer, a repairer (§9) included. Where a deployment can tell peers apart, placement also spreads a chunk across distinct *social clusters* (one person's devices, one tight friend group), so a correlated failure or collusion costs one block rather than several (§10).

---

## 7. Reading a file (GET)

1. **Resolve the root.** You were handed the root descriptor and the sealed `K`. **Check the root's author signature before using any of it**: its `level`, geometry and `tail_bytes` are read before there is anything to hash-check them against, and the AEAD tag covers the chunk's ciphertext, not the descriptor's fields. If the root's `level` is 0, it already describes file bytes. Otherwise read that chunk by steps 2–4 below; its plaintext is the descriptor list one level down. Repeat (in practice, once).
   - **Each step must strictly decrease `level`**, and the reader enforces it. Whoever supplied `(root, K)` can produce valid AEAD at every level, so authentication alone does not stop a level-ℓ root from naming a level-ℓ list; without the check, a reader can be walked through an arbitrarily long chain. With it, the descent is bounded by the `level` byte.
   - Below the root no signature check is needed: every level is reached through content-addressed ids (§4.2), so a tampered index fails its hash before it is parsed.
   - The file size is the sum of the leaves' signed `tail_bytes`.
2. **Locate blocks.** Send a have/want to the cohort for a chunk's block-ids. You need any *k* of *n*, so ask the *k* best-scoring reachable peers that answer; if some are offline, the same have/want surfaces any extra copies repair has made. A block several peers hold (a `k = 1` chunk's copies, §4.1) is asked of them in turn rather than always of the best-scoring one, so a replicated file is read over every holder's link. A peer with a negative score (§13) is asked only when no other peer has the block.
3. **Fetch and verify.** Check each block against its `block_id` (§4.2). A response that doesn't parse (a bad status byte, the wrong entry count, truncation, trailing bytes) counts as that holder's miss (§8), not the read's failure: the reader moves to the next holder, exactly as for a block the holder didn't have. The repair audit (§9) reads the same way.
4. **Decode and decrypt.** If all *k* data blocks arrived, concatenate them; otherwise RS-decode any *k* blocks to recover the chunk's ciphertext. (A `k = 1` chunk is fetched from any live holder, never decoded.) Decrypt under the chunk's `level` and index, trim to its signed `tail_bytes`, and concatenate the chunks.

Because any *k* of *n* suffice, a read succeeds with up to *m* holders offline or unwilling: no peer is on the critical path.

---

## 8. Availability and offline tolerance

Peers disappear and come back. The protocol tells a transient blip from real loss, so it doesn't churn data on every disconnect, and it does so by direct observation within the cohort rather than by a global refresh scheme.

**How liveness is observed.** Any block-holder (or the owner) periodically sends a have/want for a chunk's block-ids and notes who answers. There is no record to refresh and nothing to expire, so the picture is always current.

Because have/want is only advertisement (§5.2), the picture is **backed by occasional verification-fetches**. A holder counts as holding a block only if it recently *served* that block (or a sampled one of its blocks) and the bytes hashed to their `block_id`. A peer that advertises blocks it cannot serve is caught this way, treated as not holding them, and loses reciprocity standing (§13).

This proves a block is *retrievable*, not that the peer *dedicated storage* to it. Blocks are small, so a holder could pass by re-fetching a replica or regenerating from *k* siblings on demand (§10), which means the count measures **availability**, not *n* independent copies. Two cheap measures make faking unattractive: the fetch is **latency-bounded** (regeneration needs *k* round trips and a decode; a stored block, one disk read), and its cadence is tuned (§28) so faking costs about what honest storage costs.

**Three states per holder of a block:**

- **Live**: recently reachable *and* recently served a verification-fetch for the block (or a sampled sibling).
- **Suspected**: unreachable within a **grace window** `G` (default 24 h). *No repair.* A laptop closed overnight, a phone in a tunnel or a rebooting server sits here and recovers for free when it reappears.
- **Lost**: unreachable beyond `G`, or repeatedly failing to serve a block it advertises. Counted as missing for repair. A node may corroborate unreachability with a second observer to avoid acting on a one-sided eclipse, but need not.

Grace lives in the observer's bookkeeping, not on the wire, and skipping it is *safe*, just wasteful: repair is idempotent (§9), so a node that treats every failed audit as Lost at once merely re-spreads blocks a sleeping laptop still holds, and the surplus is reclaimed as ordinary over-replication (§14).

**Redundancy measure.** A chunk's health is one number, its **loss margin**: how many further losses it survives right now, computed from the signed id list (§4.1):

```
margin = Σ over distinct listed blocks of  min(live_holders, times listed)  −  k
```

For a coded chunk each id is listed once, so the margin is `live_blocks − k`, healthy at `n = k + m`. For a `k = 1` chunk the id is listed `m + 1` times, so the margin is `min(copies, m + 1) − 1`, healthy at `m + 1` copies. Either way the margin is `m` for a fully healthy chunk and `0` one loss from death. Repair triggers at a **low-water mark** strictly above zero (§9), never waiting until the chunk is one loss from death.

**Browser nodes** are treated as low-uptime, often-Suspected holders: they serve reads and act as extra cache while present, but durability leans on longer-lived peers. No tag is needed for that: each node measures every peer's availability itself (§13.1), placement prefers steady peers, and a copy on a peer that is reachable less than half the time does not count towards its chunk's health.

---

## 9. Self-healing / repair

Repair is per chunk. A chunk's own **block-holders** notice it decaying, and a missing copy is **rebuilt by the device that will keep it**. Anyone holding a block also holds the chunk's signed descriptor (§4.3), with the sibling block-ids and geometry, which is all it needs to audit the chunk and all another member needs to rebuild it. Reconstruction runs on ciphertext, so a repairer needs only the author's public key, never the file's key. The sharing group *reads*; any block-holder *notices*; a group member that agrees *repairs*. No peer is special or appointed.

This makes repair as redundant as the data. The peers able to notice a decaying chunk are exactly the ~`n` peers storing it, so repair works as long as any one of them is online. (Tying repair to whoever can read the file's index would make a private file's owner the only possible repairer: a single point of failure for healing even when the bytes themselves are amply redundant.)

**Nobody pushes bytes for someone else.** The only bytes a device is ever sent unasked are an author's own PUT (§6). Every other copy it holds, it fetched and rebuilt itself after agreeing to, under its own admission (§14). So a holder never has to trust a third party's claim that it is "repairing": it decides, and it charges the copy to the chunk's author like any other.

**The repair loop, run by every block-holder on a jittered interval:**

1. **Audit.** Send a have/want for the chunk's block-ids (§5) and sample a verification-fetch or two (§8) to confirm advertised blocks are retrievable. This gives the live holders of each block, and from them the chunk's **loss margin** (§8).
2. **Decide.** Repair is needed when `margin < ⌈m/2⌉`, i.e. half the redundancy is spent. Both numbers come from the descriptor, so a repairer needs no deployment config.
3. **Ask.** For every copy the chunk lacks (the target is how many times the descriptor **lists** that id, §4.1: `m + 1` for a `k = 1` chunk's lone block, 1 for each block of a coded chunk), send a `repair` request to a member of the chunk's group (§5.1) that holds none of it: the signed descriptor, the block wanted, and who holds which blocks now. The member decides under its own admission (group, sibling rule, quota, the author's allowance) and answers. Agreeing is a **promise, not a guarantee**. The asker then notes the chunk as being repaired and sends no more requests for it for a while; if the copy never lands, the note expires and a later audit asks someone else.
4. **Rebuild, on the member that agreed.** It fetches what it needs from the listed holders and rebuilds the block itself:
   - A block with a live, verified copy is copied from it.
   - A **coded** block that no live holder serves is regenerated: fetch any *k* retrievable blocks (each verified by its `block_id`, §4.2), reconstruct the chunk's ciphertext, and re-encode the **missing** block. **The regenerated block must hash to its signed `block_id`** before it is stored. This certifies the reconstruction without the key and catches any bad input or decode error, so a poisoned descriptor can never make repair mint or spread garbage.
   - A `k = 1` chunk has no parity to rebuild from, so it can only be copied while one copy survives, which is exactly what the `min` in the margin tracks.

   Its fetches are marked as this chunk's repair (`repair-fetch`, §18), so **every holder that serves one learns the chunk is being repaired** and stands down too: the duplicate-avoidance needs no message of its own. The member runs the repair after answering, never inside the request, and tries a failed fetch again with backoff while its promise lasts.
5. **Done.** The new block is discoverable via have/want at once, and redundancy is back to full with no change to the file's index, since the index never named holders.

**Duplicate work** is avoided by those repair notes and the jittered timers, not by locks. Correctness never depends on it, because repair is **idempotent**: the deterministic encoder (§4.1) regenerates the *same* content-addressed block-ids, so two members rebuilding the same block produce identical bytes, and the surplus is reclaimed as ordinary over-replication (§14).

**Moving data on availability change** is the same loop, because a chunk's margin counts only dependable copies (§8). When its holders are often offline, it falls below low water while its raw count still looks fine, and repair asks steadier members for copies before anything is lost. When the flaky copies come back as surplus, they are the ones that step down to cache (§14). Repair requests carry the chunk's margin, and a member runs the repairs it agreed to most urgent first.

**The one real cost.** A chunk can only be healed while at least one of its holders is online within a repair interval. With ~`n` holders that is a weak requirement, but it fails if all of a chunk's holders are low-uptime and go dark together (e.g. an all-browser cohort overnight). Placing at least one durable peer among each chunk's holders removes the risk (§8).

**Repair amplification is bounded.** Regenerating one lost block costs *k* block reads and one reconstruction, and only lost blocks are rebuilt. (A Locally Repairable Code cuts the *k*-read cost when it dominates, §21.) Repairing a `k = 1` chunk is a single block copy, with no reconstruction at all.

---

## 10. The redundancy invariant: no peer can make data unavailable

This requirement is **structurally bounded, but socially realized.** The structure guarantees that the *blast radius* of any one peer is small and that cheating is detectable in principle. The closed cohort (§1) is what turns that into a durability number.

**What the structure guarantees:**

- **No block is unique.** A chunk survives on any *k* of its *n* blocks, which live on distinct peers (§6). One peer holds at most one block of a chunk, so its disappearance or refusal costs at most one block, and losing a chunk takes *more than m* peers failing or defecting together. (A `k = 1` chunk is the same bound by another route: `m + 1` distinct holders, any *m* of which may be lost.)
- **No metadata is unique.** A file's index is stored exactly like its body, spread over distinct peers (§4.3), so it has the same *k*-of-*n* bound and there is no index server. The holder map is not stored at all; it is recomputed live.
- **No single repairer is required.** Any of a chunk's ~`n` holders can heal it (§9), on ciphertext, without the read key. Each chunk's shape travels as an author-signed descriptor whose author must be a peer the holder knows (§4.3), so no holder can misdirect or suppress repair, either by altering the descriptor (the signature fails) or by re-signing it under a fresh key (admission fails).
- **Withholding is detected and routed around.** A holder that stops serving fails its verification-fetches (§8), loses reciprocity standing (§13) and is skipped in future placement; its unreachability tips it to Lost and triggers repair. Active malice degrades to the same path as being offline.
- **Corruption cannot be hidden.** A tampered block fails its hash check (§4.2) and is discarded; the reader fetches another block.

**What it trusts the closed cohort for.** Three assumptions turn the bounded blast radius into an actual durability number:

- **Independence of copies.** A verification-fetch (§8) proves a block is *retrievable*, not that the peer *dedicated storage* to it. A holder could pass by re-fetching a replica or regenerating from *k* siblings on demand, so the live count measures *availability*: holders that re-serve one origin fail together. An honest cohort has no motive to do this, and latency-bounded, cadence-tuned checks (§8) make faking cost about what honest storage costs, but copy independence is ultimately *trusted, not proven*.
- **No collusion past the budget.** No more than *m* of a chunk's holders fail or defect together within a repair interval, counting jointly controlled or socially correlated peers as one failure domain. This is why placement spreads across social clusters and not merely distinct keys (§6).
- **A reachable repairer.** At least one of a chunk's holders is online within each repair interval, or nothing can heal it (§9).

The deployment's durability dial is sizing `(k, m)` (and with it the low-water mark) and the repair cadence against the cohort's real churn *and* against how many members could plausibly fail or collude together (§28). Keep the first assumption in view: in a friends-or-devices cohort it costs nothing, but in a less-trusted pool it is exactly what the §23 hardening, or a heavier proof-of-storage layer, would have to shore up.

---

## 11. Removal

When other people hold your bytes, you cannot force a remote peer to delete them. The deletion the system **guarantees** is crypto-shredding; reclaiming the disk is then a matter of letting the data age out.

**Crypto-shredding: the guarantee.** Each file has a random key (§4.4), so destroying that key makes all of its ciphertext blocks, index included, permanent noise, immediately and irreversibly. The owner and sharing group drop the sealed key from their keystores. The scope is exact: it denies *future* reads to everyone who discards the key, but it cannot reach a member who kept a sealed copy of `K` or already saved the plaintext. It is a guarantee about *confidentiality going forward among key-discarding peers*, not about erasure, and that is the only deletion the system can promise.

**Reclaiming the bytes: by eviction.** Once a file's key is gone, nobody reads its blocks, so they go cold and age out as orphans under ordinary eviction (§14). This needs no new mechanism and no authority check, because the data is already worthless. It is **best-effort and slow**: disk frees over the eviction horizon, not on command. Repair needs neither key nor permission, so a holder that keeps running repair (§9) can sustain a shredded file indefinitely. The signed tombstone of §25 *asks* holders to drop the blocks and stop repairing, but a holder can ignore it. Against an honest cohort the bytes age out; against a motivated insider, confidentiality is the real guarantee.

**Authority.** Whoever holds the key may crypto-shred: the owner and anyone they shared with each drop their own sealed copy. A member who no longer wants a file just drops its copy and stops repairing; it cannot destroy the key for everyone.

The opposite (making a key *survivable* by splitting it across the cohort so a quorum can recover it) is the optional Shamir layer of §26, which deliberately weakens this guarantee. Prompt, signed space reclamation is the optional tombstone layer of §25.

---

## 12. Donating storage

"Donate whatever storage you have" is storage's `store` facade over the host's flat-key `fs` service, plus a quota.

**The `store` facade (§16)** exposes `put(block_id, bytes)`, `get(block_id) → bytes`, `size(block_id) → n | −1` (existence is `size ≥ 0`; there is no separate `has`, mirroring the host's `fs/size`), `delete(block_id)`, `list()`, and `stat() → { quota, used, free }`. It is the `fs` service's names under storage's own key namespace. Like every granted service it exists in a realm only if the bundle manifest declares it (§2.1), so only logic that may use `fs` can reach disk. A holder stores opaque `(block_id → ciphertext)` pairs plus each block's signed descriptor (§4.3): it needs no file key and learns nothing beyond the chunk's shape.

**Backends differ by host; the protocol does not:**

- **Long-running peer:** a directory on disk; quota is a config number; effectively always Live.
- **Browser node:** OPFS or IndexedDB; quota bounded by the browser's storage budget. Blocks the browser evicts are treated as Lost and left to repair. The browser shell exposes a "donate N GB" control to set the quota.

**Quota honesty is enforced, not assumed.** No peer trusts another's advertised free space. It trusts the node's track record of *serving the data it accepted* (§8, §13): lying about capacity gets you data you then fail to serve, which costs standing. `stat()` is for the node's own accounting and admission control (declining `offer`s when full), not a figure the network trusts.

---

## 13. Reciprocity: rewarding good citizens without a coin

The reward for being a good citizen is **durability for your own data and good service from your cohort**, and what earns it is *reliably holding and serving data for others*. There is no token, no shared ledger and no global reputation object, just **direct, pairwise reciprocity**. In a closed cohort that is enough, and it is Sybil-proof: you score only peers you have actually dealt with, so identities a peer invents never enter your view.

### 13.1 The local score

Each node keeps, per peer **and per group** (§5.1), a small **decayed reciprocity balance**, built only from what it has *witnessed directly*. An observation counts in the group of the chunk it was made on:

- **Reliability**: blocks the peer has held and served, confirmed by the verification-fetches that already back repair (§8). A pass raises it; a miss lowers it more. This reuses the ordinary fetch path, with no separate challenge protocol and no proof object to store.
- **Availability**: at each repair pass, whether the peer is reachable. This measures uptime directly, so a browser tab or a laptop that is often off scores low without anyone tagging it.
- **Holdings**: how much the peer verifiably holds *for you*, against how much you hold for it. The first needs you to audit your own files, so a node keeps the signed descriptors of every file it put (no content key), and its repair loop audits them in turn as it audits the chunks it holds. That also means an owner notices, and asks for repair of, its own files.
- **Recency**: old observations decay, so a peer that stops serving fades, and the state never grows without bound.

`reputation.score(group, pubkey) → score` is a read-only query over the reliability counters. Placement (§6), repair targets (§9) and readers choosing whom to fetch from first rank peers by **reliability × availability**. A chunk's health counts only its copies on **dependable** holders, those reachable at least half the time (§8, §9). Holders deciding whether to accept an `offer` or a `repair` (§18) use holdings, below. The computation is arithmetic over locally witnessed events, so it lives in the pure, no-grant `reputation` module (§17). A deployment that stores only among one person's devices can replace it with a constant.

### 13.2 What it buys (the incentive loop)

Reciprocity is spent as **priority**, which closes the loop without money:

- **Durability for your own data.** Peers you have served reliably accept your `offer`s readily. A peer you have never reciprocated with may throttle you or ask you to contribute first.
- **A storage allowance proportional to contribution.** A soft tit-for-tat budget: the cohort durably holds for you about as much as you have reliably held for others. At a holder, an author may fill a base share of the quota plus what it verifiably holds for that holder in the group, up to the whole quota, and nothing while its reliability is negative. Leeching limits itself, and donating storage is directly valuable to the donor.
- **Preferential reads and repair.** Good citizens are chosen first to serve reads and to repair, so they get more chances to raise their score, and the loop compounds.

Honest, available nodes climb. Nodes that withhold, lie about capacity or churn destructively fail verification-fetches, decay, and get routed around (§10).

**Peers you have not dealt with** (a friend of a friend, or a node joining a new sub-cohort) are outside this local picture by design. A deployment that needs *portable, verifiable* reputation across peers who have never stored for each other adds the optional signed-receipt and transitive-trust layer of §20. The base system does not need it, which keeps reciprocity to a page of counters and keeps Sybil resistance coming from the shape of the network.

---

## 14. What to store, and what to evict

A node has finite donated space and may be offered far more than it can hold, so it needs a policy for what to accept and what to drop. This is the local face of the reciprocity loop (§13), built on **two tiers of storage**:

- **Committed**: blocks a node accepted through an `offer` (§18), whose reliable serving earns it standing (§8, §13). These are not dropped casually, since shedding one abruptly fails its next verification-fetch and loses standing. A node sheds a commitment only by **graceful release** (re-placing the block on another peer, or letting repair pick it up), accepting that durability dips until redundancy is restored.
- **Opportunistic cache**: blocks picked up while serving reads, or extra copies beyond `n`. Free to evict at any time, at no reciprocity cost.

**Admission (when an `offer` or a `repair` request arrives).** Only a chunk's author pushes its bytes; a copy for anyone else is one this node agrees to rebuild itself (§9). Either way it is charged to the author's allowance in the chunk's group, weighed by reciprocity (prefer peers who store for you) and social closeness (§5.1), and how under-replicated the chunk is may set which repairs a node takes on first. Reserve a fraction of quota for commitments so cache cannot crowd out durability, and refuse offers outright when the committed tier is full.

**Eviction (under quota pressure).**

1. Drop cache first, favoring blocks that are cold *and* **verifiably** well-replicated elsewhere. Count redundancy only from holders this node has itself recently verification-fetched (§8), or weight it by the advertiser's standing, never from raw have/want, so a peer cannot spoof abundance with cheap `have`s to make you evict the only real copy.
2. Protect rare or under-replicated blocks, the ones repair would struggle to regenerate.
3. Only if still pressed, gracefully release the lowest-value commitments, typically those for low-reciprocity peers.

Long-unserved orphan blocks, including those of a crypto-shredded file (§11), go first; that is how dead data is reclaimed without an explicit delete. (With the §25 tombstone layer, tombstoned blocks are dropped on sight.)

An eviction score like `coldness × redundancy_elsewhere × (1 / reciprocity_with_owner)`, with committed blocks weighted heavily against eviction, captures this from signals the node already tracks. The exact weighting is a tuning knob (§28). What matters is that a well-behaved node keeps what is scarce and what it owes, and sheds what is abundant and unasked for.

---

## 15. Threat model and what leaks

In a closed social cohort the main open-network threats shrink: you only peer with people you've added, so Sybil flooding and eclipse attacks are not everyday concerns. The admission policy stays restrictive (admitting any author would be remote code execution), so untrusted code never lands.

**What is protected:**

- **Content:** holders see only ciphertext (§4.4).
- **The wire:** an authenticated, encrypted channel, with each frame pinned to the channel's peer key (the seedkernel transport's authenticated key exchange and forward-secret record layer, seedkernel §12.6).
- **The content↔holder mapping:** there is no global index, and the holder map is never stored, only recomputed live within the cohort.
- **Integrity:** content addressing (§4.2) for bulk bytes, and the author's signature on the chunk descriptor (§4.3) for the shape metadata that drives repair, so a holder cannot forge it to misdirect healing.
- **Enumeration:** there is no list-all operation (§5.2). A peer can only confirm ids it is named, and without a file's key its block-ids are unguessable (except under convergent encryption, §24).

**What leaks, accepted under the closed-cohort assumption.** All of these are disclosures *to peers you chose to store with, about files you already shared with them*:

- **Inventory size**: a peer you exchange have/want with learns roughly how much you store, and a shared file's block count.
- **Per-file holdings**: a peer in a file's sharing group learns which of its blocks you hold or want.
- **Chunk shape**: a block's descriptor (§4.3) tells whoever stores it the chunk's sibling block-ids and geometry, i.e. its size and shape, never its content. The PRF-tag hardening in §23 covers this if a deployment cares.
- **Interest**: asking a key-holder for a file reveals you wanted it. A non-key-holder learns nothing, since the id is an opaque hash.
- **Social graph**: who you keep channels with is visible at the transport level. This is the residual metadata of going social, far less than a global, queryable index would expose. (The optional gossip of §20 widens it, which is one reason it is off by default.)
- **Ex-member probing**: someone who once held a file's ids can probe for those exact blocks for as long as the file is stored, because repair regenerates the same ids (§9). For sensitive files, re-encrypt under a fresh `K` on a membership change, which mints new ids (expensive, so usually done only when it matters).

Optional hardening for cohorts that are less than fully trusted is in §23. None of it is needed for a friends-or-devices cohort, and making it the default would make the system the complicated monster we are avoiding.

**Residual risk inherited from the host.** Module compute is bounded by the host: seedkernel stops a module call at the engine once the calling guest's remaining execution budget runs out, on every target (seedkernel §4.3), so a wedged `codec` or `reputation` call costs one rejected call, never the node. The storage guest is the Part I unit with the most grants (`node`, `fs`, the transport's `_net`) and the most logic, so it is the largest blast radius if storage is ever compromised. That makes it the prime audit target, and it is a standing reason for the admission policy (§19) to stay a closed allowlist rather than an open author set. Tier-2 confinement (§2.1) bounds that blast radius: a compromised guest can compute and call its granted services, nothing more.

---

## 16. What the host gives storage

Storage's confined logic reaches the world through seedkernel's one guest seam, `host.call(name, bytes)`, whose rules are seedkernel's ([RUNTIME §12.1–§12.2](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)). The granted names are the whole of Tier 1 (§2.1):

| Name | Kind | What it gives storage |
| --- | --- | --- |
| `node` | granted service | `node/sign`/`node/verify` under the slot's own scope (below); the node's public key arrives as `HOST.identity` |
| `fs` | granted service | the donated blob store (§12): flat keys to bytes in storage's own keyspace; existence is `size ≥ 0`, and `fs/stat` gives the backend's used and available bytes for the quota |
| `_net` | the transport bundle's local service | addressed request/response to a cohort peer over its authenticated channel, with a timeout; a fan-out is the guest's own concurrent sends (seedkernel §12.10) |
| `crypto/blake2b`, `crypto/chacha20poly1305-ietf/{seal,open}`, `crypto/random` | ungated host transforms | the §4.2 content hash, §4.4 authenticated encryption, and the entropy for content keys (nonces are derived, not drawn, §4.4) |
| `codec`, `reputation` | the bundle's own modules, by bare name | ungated, since they are the bundle's own verified bytes |

Time is the realm's own `Date.now()` (liveness, repair jitter, score decay). Storage adds no backend of its own.

**Crypto is reused, not added.** The transforms above are the host's. Block ids never leave storage (§4.2), so BLAKE2b-256 is storage's own choice even though the host supplies it. Key sealing (§4.4) is not on the guest seam, so it lives beside the guest, in `host/crypto.ts`, on seedstore's own `libsodium-wrappers` (the npm package on Node; in a page, the same package over the libsodium.wasm the page's host already carries). Storage ships no crypto of its own except Reed–Solomon.

**Signatures are scoped, and every signed format is tagged.** Storage signs its objects (the chunk descriptor, §4.3, and the optional tombstone, §25, file head, §27.3, and receipt, §20.1) through `node/sign` and checks them with `node/verify`. The host binds every such signature to the slot's scope, derived from the bundle's `app` label (seedkernel §12.2). So a storage signature verifies only as a storage signature, never as a bundle, a handshake or another app's object, and it verifies on every node running storage under the same label, whoever authored the bundle. Checking one needs only the signer's public key, so keyless repair (§9) is untouched. Within that scope each signed format opens with a **distinct leading tag**, so a signed object of one type can never be replayed as another. No key material ever reaches storage.

---

## 17. App logic: Tier-2, confined (§2.1)

All storage *logic* is Tier 2: confined, grant-bounded, and reaching I/O only through the §16 surface. It takes the two forms of §2.1, **WASM** for the pure hot compute and a **zero-authority JS realm** for the async orchestration, and both are bounded by the manifest's signed, human-auditable `guest.requires`, with no ambient I/O.

| Unit | Form | Grants | Role |
| --- | --- | --- | --- |
| `codec` | WASM module | none (pure) | **Reed–Solomon encode and decode** over GF(2⁸) on ciphertext blocks: the only algorithm storage ships in WASM |
| `reputation` | WASM module | none (pure) | decayed per-peer reciprocity counters from witnessed verification-fetches and served reads, and the `reputation.score` query (§13). Swapped for the §20 receipts-and-transitive-trust version when portable reputation is needed |
| **the guest** (cohort, coordinator and repair in one realm) | zero-authority JS realm | `node`, `fs`, `timer`, `_net` (`guest.requires`): its whole reach, in one signed list | **Initiator:** slicing ciphertext into `B`-byte blocks; block ids (`crypto/blake2b`); sealing and opening chunks with detached tags (§4.4); building and checking descriptors; content-key generation (`crypto/random`); PUT/GET with placement negotiation and windowed transfer; the peer set; have/want, liveness and verification-fetch sampling (§8); reciprocity accounting (§13); the repair loop (§9), and the repairs it agreed to rebuild. **Holder:** admission, the sibling rule, content addressing, quota, eviction (§14) and store writes |

The two pure modules hold **no** grants, so even if buggy they can never reach disk or network; Reed–Solomon and the trust math are exactly where you want that guarantee.

The orchestration runs in a JS realm rather than as WASM because it is inherently async and multi-step (negotiating with peers, streaming blocks, awaiting responses). The *synchronous* pure-transform module ABI (seedkernel §4) could express that only through awkward correlation-id continuations; the realm keeps it ordinary async JS while still confined to the manifest's one required set.

Discovery and placement are deliberately light: the guest keeps the peer set and runs have/want, and placement is negotiation folded into PUT. There is **no separate proof handler**: proving a holder still has data is an ordinary verification-fetch on the existing fetch path, scored locally by `reputation`.

Part I needs no replay protection of its own: every mutating request is an awaited request on the pinned, replay-protected channel (§3), and the one state-changing payload, a stored block, is idempotent by content addressing (§4.2). (The mutable head of §27.3, which is replicated rather than sent point to point, is the first object that needs a per-signer sequence, and it carries its own.)

---

## 18. Message catalog (the whole control plane: six request/response pairs)

Every storage message is a request/response between two cohort peers on the authenticated channel (§3), and there are exactly six. None carries a signature of its own, since the channel pins the sender; the only signed object in the storage protocol is the chunk descriptor riding inside `offer`, `store` and `repair` (§4.3). All but `repair` are **batched**: one message carries many blocks' worth, bounded by a per-transport byte cap (§3, §28), so round trips scale with peers, not blocks.

| Message | Request | Response |
| --- | --- | --- |
| `have` | block-ids the asker wants located (§5) | a per-id held / not-held mask (1/0) |
| `offer` | per block headed to this peer: `block_id` + its **signed descriptor** (§6) | a per-block **verdict** byte: 1 = accepted, 0 = declined, 2 = quota, 3 = sibling, 4 = descriptor rejected. Quota (§14) and the sibling rule (§6) are judged over the whole batch. Verdicts above 1 are **advisory diagnostics**: a holder may lie, so the reason never drives policy, but it turns the initiator's failure message from a guess into an exact report. |
| `store` | per accepted block: `block_id`, signed descriptor, and the bytes (§6 step 4; the bulk plane's push, §3) | a per-block **verdict** byte, with the same codes as `offer`. This is the **binding** admission point: the content address (§4.2), sibling rule and quota are checked again here, so `offer` stays advisory. |
| `fetch` | wanted block-ids (§7; also the §8 verification-fetch) | the blocks, present or absent per id (the bulk plane's pull, §3), each hash-verified by the receiver (§4.2). A block the holder has but cannot fit under its response cap is marked `UNANSWERED` (2), distinct from a miss (0), so the reader asks again. |
| `repair` | one block to rebuild: the chunk's **signed descriptor**, the `block_id` wanted, the chunk's dependable margin, and who holds which blocks now (§9) | one **verdict** byte, the codes of `offer`. Accepted is a promise to fetch, rebuild, verify and store the block. |
| `repair-fetch` | a `fetch` made while repairing a chunk, led by that chunk's key (its descriptor signature) | as `fetch`. Serving it tells the holder the chunk is being repaired (§9). |

`offer` and `store` are accepted only from the chunk's author: they are how an author places its own data. Their verdicts add 5 = holder error, 6 = over the author's allowance, 7 = not in the chunk's group (§5.1) and 8 = not the author.

PUT and GET are not messages; they are the coordinator's local API, and it speaks only these six to the cohort. Repair runs on `have`, `fetch`, `repair` and `repair-fetch` (§9). The optional verifiable-reputation layer (§20) adds `proof.challenge` / `proof.receipt` and `rep.gossip`, and the optional tombstone layer (§25) adds its signed tombstone; the base protocol uses none of them.

---

## 19. Bootstrap additions

On top of the host's own boot, a storage-capable node:

1. Boots a seedkernel node with its platform backends and its transport (seedkernel §12.8). None of this is storage-specific.
2. Wires an admission policy that admits the storage bundle: restrictive, *never* open. For example, a content-hash allowlist of the audited bundle plus a closed set of authors who may publish upgrades.
3. Admits the signed storage bundle (§2.1, §17). The pure `codec` and `reputation` modules are verified and built with it, and the guest loads into its confined realm with exactly the services the manifest's signed `guest.requires` names. An install loads code and nothing else: authority is the manifest's signature plus the operator's admission decision, never anything the code declares.
4. Joins its cohort: connects to known peers (by introduction or a rendezvous point), exchanges have/want, and starts serving.

Roles compose. A node that only *stores and serves* runs the holder side (the `fs`-backed store, admission, the sibling rule, `fetch`), and adds the repair loop and `codec` only if it will also help heal; it never needs the PUT path. A read-only client needs `codec` plus the GET path.

---

# Part II: Extensions

Everything below is **optional**. Part I is a complete, durable, private store for a cohort of friends or your own devices. Add a layer here only when a specific assumption changes: the cohort grows beyond people who have stored for each other (§20), repair bandwidth dominates cost (§21), throughput on large files matters (§22), the cohort is less than fully trusted (§23), you want cross-user dedup (§24), you need prompt rather than lazy space reclamation (§25), you need to survive losing your own keys (§26), or files change in place (§27).

## 20. Verifiable reputation: signed receipts and transitive trust

The base reciprocity score (§13) is *subjective*: your private opinion, not something you can show a third party. When a deployment needs **portable, verifiable** reputation (to judge a friend of a friend you have never stored with, or to let a node carry standing into a new sub-cohort), it upgrades the local tally to signed receipts and weights them transitively. This is strictly additive: nothing in §13 changes, and the pure `reputation` module is swapped for a richer, still grant-free, one.

### 20.1 Signed receipts (the earning event)

The earning event is the same verification-fetch §8 and §13 already perform (request a block, check it hashes to its `block_id`), but on success the challenger now emits a **signed receipt**:

```
proof.challenge:  { block_id, nonce }                        // challenger → holder (signed)
proof.receipt = signature-wrapped {
  holder_pubkey, block_id, nonce, timestamp, PASS,
}                                                            // signed by the challenger
```

Because a block is small and self-verifying, **the served block *is* the proof of retrievability**: no Merkle path or random-offset sector proof is needed. (Those exist for systems with gigabyte sectors, where transferring the whole object to check it is unaffordable.) A receipt is another signed object of the §3 kind, authority that must travel past the channel it was minted on, since its whole point is being shown to a peer that witnessed nothing. It is signed through the scoped service under its own leading format tag (§16), and carries the challenge `nonce` to resist replay. A holder accumulates receipts as a portable track record.

### 20.2 Transitive trust

A peer's reputation is computed from the receipts *others signed about it*, weighted by:

- **volume and longevity**: passing challenges for more data, over more time;
- **challenger diversity**: receipts from many *distinct* peers beat many from one;
- **recency under a hard age bound** `X`: receipts older than `X` (e.g. 90 days) are discarded, which decays a peer that stops serving and bounds how much state anyone stores;
- **retrieval success**: serving real `fetch`es, not just challenges.

The load-bearing rule: gossiped receipts (`rep.gossip`) **must be weighted transitively, never summed flat**, or a clique manufactures its own diversity by signing each other glowing receipts. Concretely, this is **EigenTrust-style transitive trust, personalized to the evaluator**. Each peer normalizes its locally witnessed scores (§13) into a trust vector, then propagates trust over the gossiped receipt graph by damped power iteration. A peer's transitive score is the fixed point of

```
trust(P) = (1 − d) · local_seed(P) + d · Σ_c trust(c) · rating_c(P)
```

restarting from the evaluator's **own** local view rather than any global pre-trusted set. Anchoring on the local seed is what makes it collusion-resistant and keeps it consistent with the subjective default: trust is computed *relative to you*, so a group with no edge into your local trust set never gains weight, and there is no global reputation object to agree on or attack. A new honest node starts near zero on the gossip path until someone's local trust reaches it. Because the local seed and every edge obey the age bound, a peer that stops serving loses both its score *and* its power to vouch for others. The computation is arithmetic over collected receipts, so it stays in the pure `reputation` module.

**Cost, and why it is optional.** This adds a stored receipt graph and a gossip path, and gossiping who challenged whom widens the social-graph disclosure of §15. A cohort of friends or your own devices needs none of it, since direct reciprocity (§13) already covers everyone you store with. Add it only when you must trust across people who have never stored for each other.

## 21. Locally Repairable Codes (LRC)

RS (§4.1) is MDS and simple: any *k* of *n* reconstruct, chunk health is one loss-margin number (§8), and the module is tiny. Its cost is **repair amplification**: healing one lost block reads *k* blocks and reconstructs the whole chunk (§9), and the common failure is exactly one lost block per chunk (§6 puts one block per peer). An **LRC** adds per-group *local* parities on top of *global* ones, so a single lost block rebuilds from its local group alone: `r ≪ k` reads and a small linear combination, with no full-chunk reconstruction. That saves bandwidth, CPU and memory, the last of which matters for browser holders.

It keeps everything RS gives seedstore (fixed content-addressed blocks, deterministic re-encode so the signed descriptor still holds, keyless ciphertext repair), unlike a rateless fountain code such as RaptorQ, which would break block content addressing outright. The price is that LRCs are **not MDS**: durability depends on the loss pattern, so the clean "any *k* of *n*" accounting of §8 and §10 becomes per-local-group health plus a global check, and §6 placement must also spread each local group across distinct peers.

The win grows with *k*: large for cold archives (`RS(20,20)` means 20-read repairs), marginal for small hot chunks. If adopted, it likely belongs as a per-chunk option, carried by the same per-file `(k, m)` override (§4.1, §28), rather than as a blanket default. Revisit if repair bandwidth turns out to dominate operating cost. (Regenerating/MSR codes cut repair bandwidth further but contact more helpers per repair, which coordinates worse under churn, so LRC is the pragmatic step.)

## 22. A dedicated bulk channel

The base bulk plane (§3) carries blocks inside the batched `store`/`fetch` messages: simplest, and entirely inside the seedkernel transport. For higher throughput on large files, a deployment can run a **dedicated bulk channel** alongside the control channel on the same connection. The control plane negotiates a transfer (block-ids, order, window) over the §18 messages, and raw blocks then stream over the bulk channel as bare frames `[claimed block_id ∥ bytes]`, where the claimed id is only a routing label. The receiver drops any frame whose claimed id it did not request (unsolicited bulk costs nothing, not even a hash), checks `block_hash(author_pk, bytes) == claimed id` on the rest, and drops mismatches: the hash, never the label, is the authority. This is the fastest option for large files, at the cost of a second channel to manage.

## 23. Hardening a less-trusted cohort

Add only if a deployment's cohort is less than fully trusted; none of this is needed for a friends-or-devices cohort.

- **PRF locator tags.** Address blocks by `tag = PRF_{K_loc}(block_id)`, with `K_loc` a per-file locator key separate from the decryption key, instead of by the raw ciphertext hash. This decouples the locator from the content hash, gives holders and observers unlinkability, and lets you rotate locators on a membership change without re-encrypting. The cost is one more per-file key and a second identifier beside every block-id. **The chunk descriptor's `block_ids` (§4.3) must then be tagged the same way**: every block-holder keeps them, so left in the clear they become cross-file linkage handles that defeat the unlinkability the tags buy. (A repairer still verifies a regenerated block by computing its raw `block_id` locally and re-applying the PRF.)
- **Size-hiding have/want.** Pad have-sets to a round number, or send them as Bloom filters, to blunt the inventory-size leak (§15). Cheap, and the right first step for a semi-trusted pool.
- **Size-hiding PSI.** A malicious-secure, size-hiding private set intersection would hide set size and non-matching elements even from an authorized but curious peer, at the cost of a multi-message protocol, real per-run latency, mandatory rate limiting and a substantial implementation. A possible future layer for genuinely semi-trusted community pools, **not** part of this design.

## 24. Convergent encryption for dedup

The base design uses a random per-file key, so two users storing the same file produce different ciphertext and there is no dedup. A deployment that wants **cross-user dedup** can opt into convergent encryption (key = hash(plaintext)), which makes identical plaintext produce identical ciphertext and identical block-ids.

The cost is more than an equality leak (a holder can tell two users stored the same content). Block-ids become a deterministic function of the plaintext, so they are no longer the unguessable noise §5.2 relies on: anyone with a candidate file can compute its block-ids and probe the cohort with have/want to **confirm** that a peer holds that exact content. Convergent mode therefore *voids* the §5.2 "can't enumerate, can't probe" guarantee for any guessable or low-entropy file. Off by default; choose it only where the dedup saving outweighs the leak.

## 25. Tombstones: prompt space reclamation

Add only if a deployment wants to reclaim disk *promptly* rather than letting crypto-shredded data age out through eviction (§11, §14); a friends-or-devices store works fine without it.

The owner publishes a **signed tombstone** for a chunk's block-ids, gossiped through the cohort. Its signed bytes open with the tombstone's own format tag (§16), so no descriptor or head can be replayed as one. A holder that receives it verifies the signature, drops the blocks, and stops counting them. Online holders comply at once and offline holders when they reconnect and see it. The tombstone also tells block-holders to **stop repairing** the chunk, so it can decay below low-water and be reclaimed instead of healed back to life. Anything a tombstone never reaches still ages out through ordinary eviction (§14).

**Authority.** A tombstone is honored only when signed by the file's author (the §2 identity), the same key that signs its descriptors (§4.3). For a shared file, only the owner's tombstone removes the data; a member who no longer wants it just drops its own copy and stops repairing.

Tombstones are bounded: a holder keeps one only until the referenced blocks are gone and a short grace period passes, so the set does not grow without limit (retention is a tuning knob, §28).

## 26. Social key recovery via Shamir sharing

Add only for files that must survive the loss of the owner's own keys. It trades away part of the §11 deletion guarantee, so it is per-file opt-in and off by default.

Crypto-shredding (§11) cuts both ways: lose `K` and *every* sealed copy of it, and the file is gone for good, which is what you want when deleting and a disaster when you merely lost your keystore. **Shamir's threshold scheme** splits `K` into `n` shares such that any `t` reconstruct it and any `t − 1` reveal *nothing* (information-theoretically). Hand the shares to `n` trusted cohort peers, and any `t` of them can later help you rebuild `K`, while no single custodian, and no colluding group smaller than `t`, ever learns it.

**It reuses the codec's arithmetic.** Shamir sharing and Reed–Solomon (§4.1) are the same construction: a value on a polynomial over GF(2⁸), recovered from enough evaluations by Lagrange interpolation. Splitting `K` byte-wise over the same field (one random degree-`t−1` polynomial per key byte) adds no new primitive or dependency, and runs in the existing no-grant `codec`. Shares are key-sized, so distribution is a handful of small sealed shares, not a bulk transfer.

**Custody, not read access.** This is distinct from sharing a file (§4.4), which seals `K` to a *reader*. A share grants nothing on its own; it is held *against future recovery*. Each share is sealed to its custodian's node key (§4.4), so an eavesdropper cannot accumulate shares, and each custodian decides independently whether to release, so recovery needs no coordinator, just `t` willing custodians.

**Who a custodian releases to.** "Release only to the file's author" is a trap: recovery happens precisely when the author's keystore is *lost*, so the requester arrives as a *new* identity that cannot prove it is the author. So, while they still hold their keys, the author registers a separate **recovery key** `R`, kept cold and apart from the operational keystore (offline, on paper, in a hardware token, or itself Shamir-split), and ships its public half in each custodian's share record, author-signed so the custodian trusts the binding. A recovery request is then **signed by `R`**, and the custodian checks it against the stored `R` rather than the lost identity.

Because `R` itself can be phished or coerced, a custodian also **announces an incoming request to the owner's other registered contacts and waits out a grace window before releasing**, so the real owner (or the cohort) can veto an impersonation before `t` shares are out. A compromised `R` is retired by registering a fresh one (a small signed update). What remains is the social risk the scheme is built on: an attacker who holds `R` (or convincingly impersonates the owner to `t` custodians) *and* survives the veto window can recover, so `t`, the custodian set and the grace window are sized against how plausibly an adversary could manage that (§28).

**The cost, and why it is opt-in.** Recoverability is the opposite of deletability: if `t` custodians can rebuild `K`, destroying your own copy no longer shreds the file, since a quorum can resurrect it. True deletion of a recoverable file means also retiring enough shares, or rotating `K`. Choose `t` against both risks at once: high enough that a colluding minority cannot recover, low enough to survive churn among the custodians. For long-lived custody, refresh shares on a membership change (proactive secret sharing) so a slowly compromised set never accumulates `t` valid shares; that refinement is unnecessary for short horizons.

---

## 27. Edits and versioning

Add only if a deployment stores *mutable* files rather than write-once blobs. A content-addressed store has no in-place mutation, so an edit is never a special operation: it is a re-PUT (§6) that reuses everything that did not change. This section adds the rules that make editing *safe* and *efficient*, plus one new object: a mutable pointer.

**An edit is a new root.** A block is named by its hash (§4.2) and a chunk by the signed descriptor over those hashes (§4.3), so a modified block is simply a *different* block, and a modified file is a *new* root. Content-addressed chunking makes this cheap: **every unchanged chunk keeps its exact block-ids**, so the new index relists blocks that are already placed, discoverable (§5) and being repaired (§9). Only the **changed** chunks are re-coded and placed (§6 steps 2–4), plus the index chunks on the path from them to the root. An append, or a same-length overwrite, touches only the trailing or overlapping chunks.

### 27.1 The nonce-reuse hazard (the rule you cannot skip)

§4.4 derives a deterministic nonce from `level ∥ index` under the file's `K`. An edit must never re-encrypt changed bytes under the old `(K, nonce)`: ChaCha20-Poly1305 nonce reuse exposes plaintext relations and breaks the authenticator. Two disciplines honor that:

- **Rotate `K` per version.** Mint a fresh content key and re-encrypt the whole file (the §23 rotation). This folds editing into crypto-shredding: the old version becomes permanent noise the moment its key is dropped (§11). The price is that a new `K` changes the ciphertext of *every* chunk, so nothing is shared across versions, and the new `K` must be re-sealed to every reader (§4.4). Right for an occasional rewrite, wrong for a one-line change to a large file.
- **Version the nonce, keep `K`.** The 12-byte nonce has seven unused bytes after `level ∥ index`, so changed chunks can draw a fresh nonce while unchanged chunks keep theirs. One construction derives those bytes from the chunk's plaintext, so different plaintext selects a different nonce; the derivation bytes ride in the signed descriptor (§4.3). Readers keep the same `K`, so distributing an edit is just handing over the new root. The trade-off is losing the rotate-to-shred coupling, plus a plaintext-equality leak across chunks under the same key.

Pick rotation for rare rewrites, versioned nonces for edit-heavy data.

### 27.2 Insert and delete: content-defined chunking

Fixed-size chunking (§4.1) groups the ciphertext by *byte offset*, so the cost of an edit depends on its shape. **Append** and **same-length overwrite** are local: only the trailing or overlapping chunks change. **Insert or delete in the middle is not**: every later byte shifts, so every following chunk and `block_id` changes, and the edit cascades down the whole tail of the file. The fix is **content-defined chunking** (Rabin-style boundaries), which derives chunk edges from the bytes, so an insert or delete perturbs only the chunks around it and the rest re-align. CDC chunks are variable-length, which no longer maps one-to-one onto RS shards (§4.1); that is paid for by normalizing each chunk before coding, and the signed descriptor and keyless repair (§9) are otherwise unchanged. Adopt CDC only if mid-file insert and delete are common.

### 27.3 The mutable head

Everything above produces a *new* root; nothing yet says **"the current version of this file."** The immutable layer deliberately has no mutable name (§4.3), so tracking the latest version needs a genuinely new object: a small **signed head** mapping a stable file identity to its current root:

```
file head (signed by the owner, the §2 identity):
  tag            // the head's distinct leading format tag (§16)
  file_id        // stable, version-independent name
  root           // the current version's root descriptor (§4.3): the signed
                 //   object itself, variable-length, not a 32-byte name
  seq            // monotonic per (signer, file_id)
```

Replay protection is the head's own `seq`, the first per-signer sequence in the design (§17): the highest `seq` from the file's author wins, and a stale or replayed head is dropped. The head is small, signed, and replicated through the cohort like any other control message; resolving a file becomes one extra hop (head → root) before the §7 GET.

**Single-writer is the easy case** (your own files across your own devices, or one owner per file), and it is all this extension covers. **Concurrent multi-writer editing is a different problem** this design does not solve: two heads at the same `seq` are a genuine conflict, and reconciling them needs last-writer-wins, a merge policy, or a CRDT over the file's index. Keep mutable files single-author unless you are prepared to build that.

### 27.4 History and reclamation

Old versions are not deleted; they are **no longer pointed at**. Each prior root stays a complete, immutable snapshot for as long as someone keeps it (and its key) and repairs it, so version history is free and tamper-evident. When a version is abandoned, the blocks **unique** to it (changed chunks that no later version relists) stop being read, go cold, and age out under ordinary eviction (§14); blocks shared with a live version keep their redundancy because a current index still names them. Prompt reclamation of a superseded version uses the existing tools: drop its key to crypto-shred it (§11), or tombstone (§25) the blocks no surviving version references. Pinning a version (a published release, a signed checkpoint) is keeping that root and refusing to let it be evicted: the §14 "protect rare blocks" rule applied deliberately.

**The cost, and why it is optional.** Write-once data (blobs, immutable media, backup snapshots) needs none of this. Mutable files cost a nonce discipline you must not get wrong (§27.1), optionally content-defined chunking (§27.2), and a new signed pointer with the usual single- versus multi-writer trade-off (§27.3). Add it only when files genuinely change in place from the user's point of view; the rest of the system never learns that a root had a predecessor.

---

## 28. Tuning knobs and open questions

- **`(k, m)` and block size `B`**: the durability/overhead dial, set once per deployment (§4.1). Size `(k, m)` against measured cohort churn, so the chance of losing more than *m* holders within one repair interval is acceptably small; a per-file override is an extension, not core. `B` sets how many blocks a file becomes, and therefore the size of its index and have/wants: larger blocks shrink the index but cost more per verification-fetch and more holder memory. Keep `B` small enough that re-fetching a whole block stays cheap, which is what lets proof of retrievability skip Merkle paths (§8, §20). A few tens to a few hundred KB is typical; no protocol constant bounds it (§3).
- **`maxMessageBytes`**: the per-node cap on one batched message (§3, §18). Operator policy, not protocol: the floor is set by the transport (a WebRTC data channel reassembles far less than a TCP link), the ceiling by how much a node, especially a browser, can hold at once. Peers may disagree on it; a mismatch costs extra round trips, never a failure.
- **Grace window `G` and liveness cadence**: set so ordinary offline patterns (overnight, commute, reboot) never trigger repair, but real departures do within a bounded time. Too short causes churn storms; too long slows healing. This includes how often, and how widely, to sample verification-fetches (§8).
- **Repair jitter**: trades healing speed against repair traffic and duplicate repair. (The low-water mark is *not* a separate knob: it is `⌈m/2⌉` of the margin each chunk's descriptor signs, §8–§9, so it moves with `(k, m)` and cannot drift out of step with the geometry it guards.)
- **Cohort uptime**: the load-bearing durability decision (§9). Each chunk's holders should include at least one well-connected, long-lived peer so repair can always run.
- **Reciprocity decay and weighting**: the half-life of the local score, and how strongly to net give against take (§13).
- **Committed/cache split and eviction weights**: how much quota a node reserves for commitments versus opportunistic cache, and the weighting of the eviction score (§14).
- **Tombstone retention** (with §25 enabled): how long a holder keeps a tombstone after the referenced blocks are gone.
- **Extensions, if enabled**: verifiable-reputation window `X`, EigenTrust damping `d`, and local-seed anchoring (§20); RS versus LRC and where, and per-file `(k, m)` overrides (§21); in-band versus dedicated bulk channel (§22); hardening choices (§23); convergent versus random-key encryption (§24); tombstones (§25); Shamir key recovery and its quorum `t` (§26); the edit nonce strategy, fixed versus content-defined chunking, and single- versus multi-writer heads (§27). All are off, RS, in-band or the deployment default unless enabled.

Everything above is expressible as modules, one confined guest, two signed objects and a restrictive admission policy, i.e. as one ordinary seedkernel bundle. The host never learns what a file is: it keeps routing the protocol id to the slot's guest while the channel pins who is speaking, the bulk bytes never enter its dispatch path, and the core stays five ideas deep: a social cohort, encryption, content addressing, erasure coding, and have/want, with reciprocity, not a coin, rewarding good citizens.
