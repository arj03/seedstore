// Meet a room's members on a seedrelay and hand them to the node's transport. Rooms are
// the app's (seedrelay's rooms.mjs); the transport knows only keys and the relays that
// reach them. seedrelay is a sibling checkout, as seedkernel is.

import { roomClient } from "../../../seedrelay/rooms.mjs";
import { netAddr, netReady, netRelay } from "../build/host/storage-node.js";

const hex = (b) => Buffer.from(b).toString("hex");

/** Register `shell`'s node on the relay at `relay` (`ws://host:port`) and stay in `room`
 *  there: each member goes into the address book behind that relay under `secret`, the
 *  room's shared contact secret, and the smaller key of each pair dials. A private relay
 *  (seedrelay's `--secret`) also wants `relaySecret`, which the transport and the room
 *  client prove with BLAKE2b and never send. Resolves to the room client, once registered. */
export async function joinRelayRoom({ shell, identity, sodium, relay, room, secret, relaySecret }) {
  if (typeof WebSocket === "undefined") {
    throw new Error("a relay room needs a global WebSocket: Node 22+, or node --experimental-websocket");
  }
  await netRelay(shell, relay, relaySecret);
  const me = hex(identity.publicKey);
  const client = roomClient({
    relay,
    publicKey: identity.publicKey,
    sign: (m) => sodium.crypto_sign_detached(m, identity.privateKey),
    ...(relaySecret ? { secret: relaySecret, blake2b: (m) => sodium.crypto_generichash(64, m) } : {}),
    onMember: (_room, key, present) => {
      if (!present || key === me) return;
      void netAddr(shell, key, "relay+" + relay, secret)
        .then(() => (me < key ? netReady(shell, 0) : undefined))
        .catch(() => {});
    },
  });
  await client.join(room);
  return client;
}
