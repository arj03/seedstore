// Meet a room's members on a seedrelay and hand them to the node's transport. Rooms are
// the app's (seedrelay's rooms.mjs); the transport knows only keys and the relays that
// reach them. seedrelay is a sibling checkout, as seedkernel is.

import { roomClient } from "../../../seedrelay/rooms.mjs";
import { netAddr, netReady, netRelay } from "../build/host/storage-node.js";
import { toHex } from "../build/host/util.js";

/** The roster a room implies: one group, `name`, of this node and every member it has met
 *  there, kept on `node` as they appear. Pass the answer as joinRelayRoom's `onMember`. The
 *  room's contact secret is what gates who can be met. */
export function roomGroup(node, name) {
  const members = new Set([node.peerId]);
  let pending = node.setGroups({ [name]: [...members] });
  return (key) => {
    if (members.has(key)) return;
    members.add(key);
    pending = pending.then(() => node.setGroups({ [name]: [...members] })).catch(() => {});
  };
}

/** Register `shell`'s node on the relay at `relay` (`ws://host:port`) and stay in `room`
 *  there: each member goes into the address book behind that relay under `secret`, the
 *  room's shared contact secret, and the smaller key of each pair dials. A private relay
 *  (seedrelay's `--secret`) also wants `relaySecret`, which the transport and the room
 *  client prove with BLAKE2b and never send. `onMember(key)` hears each member that
 *  appears. Resolves to the room client, once registered. */
export async function joinRelayRoom({ shell, identity, sodium, relay, room, secret, relaySecret, onMember = () => {} }) {
  if (typeof WebSocket === "undefined") {
    throw new Error("a relay room needs a global WebSocket: Node 22+, or node --experimental-websocket");
  }
  await netRelay(shell, relay, relaySecret);
  const me = toHex(identity.publicKey);
  const client = roomClient({
    relay,
    publicKey: identity.publicKey,
    sign: (m) => sodium.crypto_sign_detached(m, identity.privateKey),
    ...(relaySecret ? { secret: relaySecret, blake2b: (m) => sodium.crypto_generichash(64, m) } : {}),
    onMember: (_room, key, present) => {
      if (!present || key === me) return;
      onMember(key);
      void netAddr(shell, key, "relay+" + relay, secret)
        .then(() => (me < key ? netReady(shell, 0) : undefined))
        .catch(() => {});
    },
  });
  await client.join(room);
  return client;
}
