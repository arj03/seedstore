// One storage node in this process, as the command-line tools stand it up (p2p-cli,
// serve-holder, seedstore): a seedkernel shell over the sockets given, the seedstore bundle
// on it, and its peers taught, dialed and put in one group.

import { bootShell } from "seedkernel-wasm/shell-core";
import { MemoryFs } from "seedkernel-wasm/fs-memory";
import { NodeFs } from "seedkernel-wasm/fs-node";
import { createStorageNode, storageRuntime, netPeer, netReady, netRelay } from "../build/host/node.js";
import { DEFAULT_QUOTA_BYTES } from "../build/host/core.js";

/** `"pk[.secret]@dest, …"` as specs; a bare `pk[.secret]` is reached through `relay`. */
export function peerSpecs(arg, relay) {
  return (arg ?? "").split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
    .map((s) => (relay && !s.includes("@") ? `${s}@relay+${relay}` : s));
}

/**
 * `sodium` is the shell's crypto (seedkernel-wasm `loadCrypto`, which p2p-cli wraps to time
 * the record layer). `dir` keeps the store on disk, in memory when omitted. `peers` are
 * specs (`peerSpecs`); with `group`, the roster is that group of this node and them.
 * Resolves once every peer linked or `readyMs` passed: `peers` are their ids, `linked`
 * those up.
 */
export async function bootNode({
  identity, sodium, channels, datagrams, dir, connsPerPeer, timeoutMs, contactSecret,
  config, quota = DEFAULT_QUOTA_BYTES, guestDeadlineMs, relay, relaySecret, peers = [], group, readyMs = 10000,
}) {
  const fs = dir ? new NodeFs(dir) : new MemoryFs();
  const runtime = await storageRuntime((cfg) => bootShell({ ...cfg, sodium, services: { fs, transport: cfg.transport } }),
    { identity, channels, datagrams, connsPerPeer, timeoutMs, contactSecret });
  const node = await createStorageNode({ runtime, config, quota, guestDeadlineMs });
  const relayState = relay ? await netRelay(runtime.shell, relay, relaySecret) : null;
  const ids = [];
  for (const spec of peers) ids.push(await netPeer(runtime.shell, spec, "ws"));
  if (ids.length > 0) await netReady(runtime.shell, readyMs);
  const linked = new Set(await node.linkedPeers());
  if (group) await node.setGroups({ [group]: [node.peerId, ...ids.filter((id) => id !== node.peerId)] });
  return { node, runtime, peers: ids, linked, relayState };
}
