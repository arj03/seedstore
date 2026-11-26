# seedstore: a file storage app for [seedkernel](https://github.com/arj03/seedkernel)

Private, self-healing peer-to-peer file storage for a group of peers who know each
other: your own devices, your friends, or an explicit storage group.

You hand seedstore a file. It encrypts the file on your machine, erasure-codes the
ciphertext, and spreads the pieces across your peers so that no single peer can make
the file unavailable. Peers can be offline for a while without losing data. When
redundancy drops, the remaining holders rebuild the missing pieces, and they do it
without being able to read the file. Peers that store and serve reliably for others
get reliable storage back, with no coin involved.

Seedstore ships as one signed bundle, `seedstore.skb`, that the generic seedkernel host
loads. It is not a separate binary, and it runs the same way in Node, the browser and
seedkernel's native binary.

More in [docs/](docs/): [SPEC](docs/SPEC.md) (the design: data model, protocol, repair,
threat model and the optional extensions), [ARCHITECTURE](docs/ARCHITECTURE.md) (how the
implementation is put together, and where it departs from the spec) and
[PERFORMANCE](docs/PERFORMANCE.md) (throughput, how to reproduce it, and the tuning notes).

> **Status:** experimental. [`WASM/`](WASM/) implements Part I of the spec, the minimal
> system, except for the pieces listed under
> [not yet built](docs/ARCHITECTURE.md#not-yet-built), such as a read cache and reclaiming
> removed files. The optional Part II extensions are not implemented. The wire format still
> changes without a compatibility promise.

## How it works

The whole design rests on five ideas:

- **A social cohort.** You store only with a bounded set of peers you have a
  relationship with, kept as named groups such as your own devices and your friends.
  A file lives in one group, and a peer outside your groups is answered nothing.
  There is no global index or DHT, so strangers can't find or probe your data.
- **Client-side encryption.** Every file gets a random key, and holders only ever
  see ciphertext. You share a file by sealing its key to a friend's public key.
  Destroying the key makes every copy permanent noise.
- **Content addressing.** A block is named by the hash of its bytes, so a block that
  has been tampered with doesn't match its name and is dropped. Bulk data needs no
  signatures.
- **Erasure coding.** Reed–Solomon `RS(k, m)` turns each chunk into `k + m` blocks on
  distinct peers, and any `k` of them rebuild the chunk. The default `RS(2, 2)`
  survives 2 lost holders at 2× storage cost and needs only 4 peers per chunk. A cohort
  of 16 or more can run `RS(10, 6)` with blocks under 200 KiB, which survives 6 at 1.6×.
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
rebuild it without the file key. Only seedkernel's host services (filesystem, signing,
network link) do real I/O; all storage logic runs confined, so upgrading seedstore
changes signed content, not what you trust.

## Quick start

It needs Node ≥ 22 and a seedkernel checkout beside this one, which it uses as a `file:`
dependency (`../seedkernel/WASM`).

```sh
cd ../seedkernel/WASM && npm install && npm run build
cd ../../seedstore/WASM && npm install && npm run build
npm test
npm run serve:demo     # http://localhost:3000/index.html
```

The in-tab demo boots a small cohort inside one page: store a file, take peers offline,
and watch repair restore redundancy.

The first build mints the bundle author key `seedstore-author.key`, and
`seedstore-author.version`, the bundle's version, which hosts refuse to go back from.
**Back them up together.** Both are gitignored.

## Running nodes

A node is the `seedkernel` binary (from the [seedkernel
release](https://github.com/arj03/seedkernel/releases/latest), 0.1 or later, or built in
`../seedkernel/native`) with the seedstore bundle. A host runs only bundles from authors
its policy names: `WASM/bundle-policy.json` names this repo's author, and a bundle built
under your own key prints its author for a policy of your own. Every command below runs
from `WASM/`.

A holder stores only for the keys in its groups. Start one:

```sh
echo '{ "quota": 8589934592, "groups": { "cohort": ["<client key>"] } }' > holder.json
seedkernel --policy bundle-policy.json --bundle bundle/seedstore.skb --local-config holder.json \
  --dir ./data-A --key ./A.key --listen 0.0.0.0:7401,quic=udp://0.0.0.0:7402
```

```
seedkernel-native <holder key>
  …
  tcp    listening on :7401
  quic   listening on :7402 (udp)
  contact <secret>
  bundle seedstore v…  author <author key>  serves seedstore
```

Its key is kept in `A.key`, so it is the same node next time. A peer dials it as
`<holder key>.<contact>@host:7401`, or `@quic://<ip>:7402`; without the contact secret it
gets silence. Start as many holders as the geometry needs (4 for `RS(2, 2)`), then put
and get from a client whose own groups list them:

```sh
echo '{ "groups": { "cohort": ["<key A>", "<key B>", "<key C>", "<key D>"] } }' > client.json
PEERS="<key A>.<contact A>@host:7401,<key B>.<contact B>@host:7403,…"
seedkernel --policy bundle-policy.json --bundle bundle/seedstore.skb --local-config client.json \
  --dir ./client --key ./client.key --peers "$PEERS" --op put < notes.txt > notes.token
seedkernel --policy bundle-policy.json --bundle bundle/seedstore.skb --local-config client.json \
  --dir ./client --key ./client.key --peers "$PEERS" --op get < notes.token > restored.txt
```

A node prints its key when it starts, so start the client once to learn the key the
holders' groups need. `--op put` answers the file token, `<root hex>:<key hex>`, and
`--op get` takes it back. Keep tokens private: a token reads the file, and without its
key the holders hold permanent noise.

`--op` hands the guest the whole file in one call. For a large file, and for asking a node
what it stores, use `scripts/seedstore.mjs`, which streams a file in windows. With `--dir`
it asks the node serving that directory, or boots one there; with `--peers` alone it
boots one in memory. On Windows it cannot reach a running native node, so ask that one
with `seedkernel --dir <dir> --op holdings` (or `files`, `placement`, `probe`):

```sh
node scripts/seedstore.mjs put photo.jpg --peers "$PEERS" --dir client --save photo.token
node scripts/seedstore.mjs get photo.token --peers "$PEERS" --out photo.jpg
node scripts/seedstore.mjs where --peers "$PEERS" --dir client --live   # who keeps each chunk
node scripts/seedstore.mjs holdings --dir ./data-A       # what a holder keeps, for whom
```

## Settings

A node's local config, `--local-config <file>`, is operator policy and overrides the
bundle's signed defaults. Every key is optional.

| Key | Default | Meaning |
| --- | --- | --- |
| `quota` | none | Bytes this node stores for others. Without it a `seedkernel` node stores nothing; the scripts' nodes default to 64 MiB. |
| `groups` | `{}` | Named groups of peer keys (hex), `{ "cohort": ["<key>", …] }`. A node stores for and answers only these peers, and a PUT goes into one group. A group can also retire keys, `{ "cohort": { "keys": [...], "retired": [...] } }`: a retired key can no longer send or place anything, but the files it put are still kept and repaired. |
| `newcomerShare` | `0.5` | The share of `quota` an author with no standing here may fill. `1` turns the allowance off, for one person's own devices. |
| `k`, `m` | `2`, `2` | The Reed–Solomon geometry of new files. Each chunk records its own, so readers and repairers need no config. |
| `blockSize` | 524288 | Bytes per block. A file's last chunk uses smaller blocks. |
| `maxMessageBytes` | 1048576 | The largest OFFER, STORE or FETCH message. |
| `fanoutWindow` | `16` | Requests in flight per holder during a PUT or GET. |
| `windowTargetBytes` | ~10.7 MiB | Plaintext per streamed PUT or GET window; two are in flight in the guest. |
| `verifyFreshMs` | 900000 | How long a holder that passed a verification fetch counts as live. |
| `verifyDeadlineMs` | 30000 | How long a verification fetch may take before it fails. |

The host's own flags set the rest: `--guest-memory` (MiB for the guest realm),
`--guest-timeout` (ms one guest invocation may run, 5000 by default), and
`--transport-config` (`connsPerPeer`, `requestTimeoutMs`, `peers`).

## Browser demos

```sh
npm run serve:demo      # builds build/browser-demo, serves it on :3000
#   http://localhost:3000/index.html   in-tab cohort
#   http://localhost:3000/p2p.html     a real node against real holders
```

**`p2p.html`** makes the tab a full storage node, storing with RS(1,1) across the other
nodes. It reaches holders one of two ways:

- **Direct WebSocket.** Start holders with `--listen ws=0.0.0.0:47210 …` and paste each
  one's `<key>[.<contact>]@host:port` into the peers box. They form the tab's `room`
  group, and each holder must list the tab's key, which the page logs, in its own
  `groups.room`.
- **WebRTC.** Peers meet in a room on a [seedrelay](https://github.com/arj03/seedrelay),
  link through it, and move to a direct connection where STUN can punch one. Open three
  or more tabs in one room, or one tab plus console holders:

  ```sh
  (cd ../../seedshell && npm run relay)   # prints ws://<relay key>.<secret>@127.0.0.1:8080
  RELAY=ws://<relay key>.<secret>@127.0.0.1:8080 npm run serve:holder   # run two
  ```

A tab's block store is in RAM, so a tab acting as a holder forgets everything on reload:
treat the browser as the file's owner, and let `seedkernel` or console holders keep the
bytes.

## Use it as a library

```js
import { createConnectedCohort, loadSodium, loadWasmBytes, LoopbackNetwork } from "./build/host/node.js";

const nodes = await createConnectedCohort({ count: 6, network: new LoopbackNetwork(),
  sodium: await loadSodium(), wasm: await loadWasmBytes(), config: { k: 2, m: 2, blockSize: 512 } });
const put = await nodes[0].put(new TextEncoder().encode("hello, cohort"));
const got = await nodes[0].get(put.root, put.key);
```

`LoopbackNetwork` runs the real transport bundle over in-memory channel pairs, so an
in-process cohort exercises the shipped stack. A node's groups are `groups` at boot, or
`setGroups` later, and a PUT into one of several names it: `put(data, { group })`.

## Scripts

From `WASM/`:

| Script | What it does |
| --- | --- |
| `npm run build` | Builds the codec and reputation WASM, the host, the guest and the minified host, and signs `bundle/seedstore.skb`. |
| `npm test` | Builds, then runs the suite on Node. [ARCHITECTURE](docs/ARCHITECTURE.md#tests) lists what each suite covers. |
| `npm run serve:demo` | Builds the browser demos and serves them on port 3000. |
| `npm run serve:holder` | A console holder in a relay room (`RELAY=…`, `ROOM=…`). |
| `npm run smoke:relay` | PUT and GET headless through a relay, then over UDP, against the sibling seedrelay. |
| `npm run clean` | Deletes `build/`. |
| `node scripts/seedstore.mjs` | `put`, `get`, `ls`, `where`, `holdings` and `probe` against a node. |
| `node scripts/p2p-cli.mjs` | The PUT/GET benchmark from Node against live holders. |
| `bash scripts/bench-native/run.sh` | The PUT/GET benchmark with native nodes throughout ([PERFORMANCE](docs/PERFORMANCE.md)). |

## Troubleshooting

- **A peer never links.** Its address lacks its contact secret, or names the wrong key:
  a gated node answers a wrong or missing secret with silence.
- **A put fails with `holders declined (… not-in-group)`.** A holder's `groups` must list
  both the author and the node sending, under the group the PUT names.
- **`declined (… quota)` or `(… allowance)`.** The holder is full, or this author has used
  its share there: raise `quota` or `newcomerShare` on the holder.
- **`declined (… descriptor-rejected)`.** The holder runs another or an older seedstore
  bundle. Give it the current one.
- **`no holder returned a verdict — the requests timed out`.** A large PUT over a slow
  link queued past the deadline: raise seedkernel's `--guest-timeout`, or p2p-cli's
  `--timeout`.
- **`guest: handoff deadline exhausted before host.call`.** One streamed window took
  longer than the guest deadline. Raise `--guest-timeout` (p2p-cli's
  `--guest-deadline`).
- **`UNDER-REPLICATED` after a put.** The group has fewer linked holders than `k + m`, or
  one declined. Repair tops it up once more holders are linked.
- **A node is slow to answer its first request after a restart.** A store with no saved
  index yet reads every record once; later restarts read `store.idx`.
- **The browser demo behaves like old code after a change.** It serves the build: rerun
  `npm run serve:demo`, and hard-reload.
