// Meet a room's members on a seedrelay and hand them to the node's transport. Rooms are
// the app's (seedrelay's rooms.mjs); the transport knows only keys and the relays that
// reach them. seedrelay is a sibling checkout, as seedkernel is.

import { roomClient, roomSecret } from "../../../seedrelay/rooms.mjs";
import { netAddr, netReady, netRelay, netSecrets, netTell } from "../build/host/storage-node.js";
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

/** A status hook to boot a node with (`bootNode`'s `onStatus`), which `joinRelayRoom`
 *  then hands its room client: rooms travel on the node's own relay link. */
export function relayStatus() {
  const feed = { client: null, onStatus: (s) => feed.client?.status(s) };
  return feed;
}

/** Register `shell`'s node on the relay at `relay` (`ws://<key>.<secret>@host:port`) and
 *  stay in `room` there: each member goes into the address book behind that relay under
 *  `secret`, the room's shared contact secret, by default the room's own (seedrelay's
 *  `roomSecret`), which the node also answers to, and the smaller key of each pair dials.
 *  `relaySecret` stands in for one the relay's URL carries, in hex, which the transport
 *  proves and never sends. `status` is the node's `relayStatus`.
 *  `onMember(key)` hears each member that appears. Resolves to the room client, once
 *  registered. */
export async function joinRelayRoom({ shell, identity, relay, room, secret, relaySecret, status, onMember = () => {} }) {
  const me = toHex(identity.publicKey);
  const roomKey = secret ?? await roomSecret(room);
  await netSecrets(shell, [roomKey]);
  const client = status.client = roomClient({
    tell: (bytes) => netTell(shell, bytes),
    onMember: (_room, key, present) => {
      if (!present || key === me) return;
      onMember(key);
      void netAddr(shell, key, "relay+" + relay, roomKey)
        .then(() => (me < key ? netReady(shell, 0) : undefined))
        .catch(() => {});
    },
  });
  await netRelay(shell, relay, relaySecret);
  await client.join(room);
  return client;
}
