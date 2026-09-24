# seedstore: a file storage app for [seedkernel](https://github.com/arj03/seedkernel)

Private, self-healing peer-to-peer file storage for a group of peers who know each
other: your own devices, your friends, or an explicit storage group.

You hand seedstore a file. It encrypts the file on your machine, erasure-codes the
ciphertext, and spreads the pieces across your peers so that no single peer can make
the file unavailable. Peers can be offline for a while without losing data. When
redundancy drops, the remaining holders rebuild the missing pieces, and they do it
without being able to read the file. Peers that store and serve reliably for others
get reliable storage back, with no coin involved.

Seedstore runs on [seedkernel](https://github.com/arj03/seedkernel). It ships as one
signed bundle that the generic seedkernel host loads. It is not a separate binary,
and it runs the same way in Node, Bun and the browser.

> **Status:** experimental. [`WASM/`](WASM/) implements Part I of the spec, the complete
> minimal system. The optional Part II extensions are not implemented. The wire format
> still changes without a compatibility promise.

## How it works

The whole design rests on five ideas:

- **A social cohort.** You store only with a bounded set of peers you have a
  relationship with. There is no global index or DHT, so strangers can't find or
  probe your data.
- **Client-side encryption.** Every file gets a random key, and holders only ever
  see ciphertext. You share a file by sealing its key to a friend's public key.
  Destroying the key makes every copy permanent noise.
- **Content addressing.** A block is named by the hash of its bytes, so a block that
  has been tampered with doesn't match its name and is dropped. Bulk data needs no
  signatures.
- **Erasure coding.** Reed–Solomon `RS(k, m)` turns each chunk into `k + m` blocks on
  distinct peers, and any `k` of them rebuild the chunk. The default `RS(10, 6)`
  survives 6 lost holders at 1.6× storage cost.
- **A have/want exchange.** "Who has these block ids?" is the whole discovery layer.
  Holders are found live, so nothing about who holds what goes stale.

```
file ─encrypt─► ciphertext ─split─► k data blocks ─RS(k,m)─► k+m blocks
                                                               │
                        offer / store to distinct cohort peers ▼
                                                     one block per holder
                                                               │
     GET: have/want → fetch any k → verify hashes → decode → decrypt
```

A file is described by a small **signed chunk descriptor** that lists its block ids.
A large file's list of descriptors is stored the same way as file data, so what you
hand a reader is one root descriptor plus the content key. Any peer holding a block
also holds that chunk's descriptor, so any holder can check the chunk's health and
rebuild it without the file key.

The trusted part is small. Only seedkernel's host services (filesystem, signing,
network link) do real I/O. All storage logic runs confined: the Reed–Solomon codec
and the reputation math are no-grant WASM modules, and the protocol runs in a
zero-authority JS realm. So upgrading seedstore changes signed content, not what
you trust.

## Quick start

Seedstore builds against a sibling checkout of
[seedkernel](https://github.com/arj03/seedkernel); the WebRTC demo also needs a
[seedrelay](https://github.com/arj03/seedrelay) server to signal through:

```
GitHub/
  seedkernel/
  seedstore/
```

```sh
(cd seedkernel/WASM && npm install && npm run build)
cd seedstore/WASM
npm install
npm test               # builds everything, then runs the suite
npm run serve:demo     # browser demo → http://localhost:3000/index.html
```

The in-tab demo (`index.html`) boots a small cohort inside one page. You can store a
file, take peers offline, and watch repair restore redundancy. `p2p.html` makes the
tab a real node against real holders. To run nodes from the command line, to embed
seedstore as a library, and for the browser transports, see the
[implementation README](WASM/README.md).

## Repository

| Path | What it is |
| --- | --- |
| [`docs/SPEC.md`](docs/SPEC.md) | The design spec: data model, protocol, repair, threat model, and the optional extensions. Code comments cite it as `SPEC §n`. |
| [`WASM/`](WASM/) | The implementation: AssemblyScript codec and reputation modules, the confined guest, the host glue, tests, and the browser demos. |
| [`WASM/README.md`](WASM/README.md) | How to build, run, embed and test it, plus the code map. |
| [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) | Codec and end-to-end throughput numbers, how to reproduce them, and what we learned tuning them. |

## Where to start reading the spec

- **§1–§2.1**: the goals, the closed-network assumption, and the trust tiers.
- **§4**: the data model, meaning blocks, chunks, the signed descriptor and encryption.
- **§6–§9**: PUT, GET, availability and self-healing.
- **§15**: what the design protects and what it leaks.
- **§18**: the entire control plane, which is four request/response messages.
- **Part II (§20–§27)**: optional extensions such as verifiable reputation, LRC,
  tombstones, Shamir key recovery and edits.
