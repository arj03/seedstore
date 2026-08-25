// A werift-backed RTCPeerConnection for the *console* side of the kernel's RtcNetwork.
//
// `seedkernel-wasm/net-rtc` is browser-native and drives the W3C surface; this is the Node
// side of that swap, in pure JS with werift (no native addon, so it also bundles into a
// `bun --compile` shell), wired through the single `peerConnectionFactory` seam RtcNetwork
// exposes:
//
//   browser tab  ──RTCDataChannel──┐
//                                  ├── relay (signaling only) ── same room
//   console node ──werift DC───────┘
//
// The whole job is an impedance match: werift speaks an rxjs-style `.subscribe()` API,
// delivers Buffers, wants explicit createOffer/createAnswer and exposes no `binaryType`.
// The facade means the kernel needs zero werift-specific code — it owes `openLink` a byte
// duplex, and this is one implementation of that duplex. The transport's in-channel
// handshake still does the real authentication; werift's DTLS only has to bring up *a*
// channel, so nothing here carries security weight.
//
// It lives here rather than in the kernel because werift (~19 MB with its DTLS/SRTP
// dependency tree) is a console-only concern: the browser never takes this path, and
// scripts/smoke-rtc.mjs — a real ICE → DTLS → SCTP round trip on loopback — is the only
// thing that exercises it.
//
// Node/Bun only (it needs werift and a global Buffer).
import { RTCPeerConnection as WeriftPeerConnection } from "werift";

// RtcNetwork/RtcChannel only ever addEventListener (never remove), so a type→listeners map
// is the whole contract. dispatch() tolerates a throwing listener so one bad handler cannot
// wedge the connection.
class Emitter {
    #listeners = new Map();

    addEventListener(type, cb) {
        const arr = this.#listeners.get(type);
        if (arr)
            arr.push(cb);
        else
            this.#listeners.set(type, [cb]);
    }
    dispatch(type, ev) {
        for (const cb of this.#listeners.get(type) ?? []) {
            try {
                cb(ev);
            }
            catch { /* a listener must not break the channel */ }
        }
    }
}
// ── RTCDataChannel facade over a werift data channel ──────────────────────────
// MessageChannel (the kernel's net-channel.ts) consumes binaryType, addEventListener,
// send(Uint8Array), close() and an optional bufferedAmount; werift offers
// .onMessage/.stateChanged/.error and a Buffer-only send.
export class WeriftRtcDataChannel extends Emitter {
    dc;
    // RtcChannel sets this to "arraybuffer"; werift always hands us a Buffer, so it
    // is purely cosmetic — stored to satisfy the assignment, never read.
    binaryType = "arraybuffer";
    opened = false;
    constructor(dc) {
        super();
        this.dc = dc;
        // A Buffer is a Uint8Array, so the channel's `new Uint8Array(ev.data)` copies
        // correctly and its string test still separates a text frame from a binary one.
        dc.onMessage.subscribe((data) => this.dispatch("message", { data }));
        dc.stateChanged.subscribe((state) => {
            if (state === "open")
                this.markOpen();
            else if (state === "closed")
                this.dispatch("close");
        });
        dc.error.subscribe(() => this.dispatch("error"));
        // A channel received via ondatachannel can already be "open" before we subscribe;
        // surface that on a microtask so RtcChannel, constructed right after us, has its
        // "open" listener registered first.
        if (dc.readyState === "open")
            queueMicrotask(() => this.markOpen());
    }
    markOpen() {
        if (this.opened)
            return; // stateChanged + the already-open guard can race
        this.opened = true;
        this.dispatch("open");
    }
    send(bytes) { this.dc.send(Buffer.from(bytes)); }
    close() { this.dc.close(); }
}
// ── RTCPeerConnection facade over a werift peer connection ─────────────────────
class WeriftRtcPeerConnection extends Emitter {
    pc;
    constructor(config) {
        super();
        this.pc = new WeriftPeerConnection(config);
        // Trickle ICE: werift emits each gathered candidate and a final `undefined`, which
        // RtcNetwork's `if (ev.candidate)` guard drops. Its RTCIceCandidate.toJSON() is
        // already the standard init a browser accepts.
        this.pc.onIceCandidate.subscribe((candidate) => this.dispatch("icecandidate", { candidate }));
        this.pc.onDataChannel.subscribe((channel) => this.dispatch("datachannel", { channel: new WeriftRtcDataChannel(channel) }));
        this.pc.connectionStateChange.subscribe(() => this.dispatch("connectionstatechange"));
    }
    createDataChannel(label, opts) {
        const dc = this.pc.createDataChannel(label, opts);
        // `negotiationneeded` is RtcNetwork's single entry point for making an offer.
        // werift's own has looser timing, so it is synthesised here — deterministic, and
        // exactly once per dial.
        queueMicrotask(() => this.dispatch("negotiationneeded"));
        return new WeriftRtcDataChannel(dc);
    }
    // The W3C "implicit" form RtcNetwork relies on. werift needs the description spelled
    // out, so pick offer vs answer from the signaling state.
    async setLocalDescription() {
        const desc = this.pc.signalingState === "have-remote-offer"
            ? await this.pc.createAnswer()
            : await this.pc.createOffer();
        await this.pc.setLocalDescription(desc);
    }
    async setRemoteDescription(desc) { await this.pc.setRemoteDescription(desc); }
    async addIceCandidate(candidate) { await this.pc.addIceCandidate(candidate); }
    get signalingState() { return this.pc.signalingState; }
    get connectionState() { return this.pc.connectionState; }
    get localDescription() { return norm(this.pc.localDescription); }
    get remoteDescription() { return norm(this.pc.remoteDescription); }
    // werift close() is async; RtcNetwork calls close() synchronously inside its own
    // try/catch teardown, so we fire-and-forget.
    close() { void this.pc.close(); }
}
function norm(d) {
    return d ? { type: d.type, sdp: d.sdp } : null;
}
// Translate a W3C RTCConfiguration into werift's PeerConfig. The only real mismatch is
// iceServers.urls — `string | string[]` there, a single `string` here — so a multi-URL
// entry fans out into one werift server each.
function translateConfig(config, extra) {
    const iceServers = [];
    for (const s of config?.iceServers ?? []) {
        const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
        for (const u of urls) {
            iceServers.push({
                urls: u,
                ...(s.username !== undefined ? { username: s.username } : {}),
                ...(s.credential !== undefined ? { credential: String(s.credential) } : {}),
            });
        }
    }
    return { ...(iceServers.length ? { iceServers } : {}), ...extra };
}
/** A `peerConnectionFactory` for RtcNetworkOptions backed by werift, so a Node or
 *  Bun process drives the very same RtcNetwork as a browser tab and joins the
 *  same relay room. `extra` passes werift-only PeerConfig through untouched —
 *  e.g. `{ iceAdditionalHostAddresses: ["127.0.0.1"] }` to make two peers on one
 *  machine connect with no STUN, or an `icePortRange` to pin the UDP ports. */
export function weriftPeerConnectionFactory(extra = {}) {
    // The facade is a structural subset of RTCPeerConnection — only what RtcNetwork
    // actually touches.
    return (config) => new WeriftRtcPeerConnection(translateConfig(config, extra));
}
