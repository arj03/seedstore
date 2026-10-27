// The seedstore bundle's client surface (SPEC §18.1), over any `invoke`: an in-process
// node's AppHandle, or a running node reached through seedkernel's control endpoint. The
// guest owns every answer; this file only frames the ops and types what comes back.

import { writeOp } from "seedkernel-wasm/op-frame";
import { Op, decodePutResult, type PutResult } from "./protocol.js";
import { groupBytes } from "./descriptor-core.js";
import { readU32BE, readU64BE, concatBytes } from "./util.js";

/** One op frame (`[opLen u8][op][args]`) in, the guest's answer out. */
export type Invoke = (frame: Uint8Array) => Promise<Uint8Array>;

/** The version every client-op answer carries; a different one is refused. */
export const CLIENT_VERSION = 1;

/** One of this node's own files. `root` is its root descriptor, what a GET starts from. */
export interface FileInfo {
  root: string;
  /** The root's chunk key, which names the file's records. */
  id: string;
  bytes: number;
  chunks: number;
  index: number;
  group: string;
  k: number;
  m: number;
  blockSize: number;
}

/** Decayed [passes, misses] as this node last recorded them, or null if never observed. */
export type Counts = [number, number] | null;

export interface FilePlacement extends FileInfo {
  healthy: number;
  short: number;
  unaudited: number;
  /** Every member of the file's group, and any other peer holding part of it. */
  peers: Record<string, { holds: number; member: boolean; reliability: Counts; availability: Counts }>;
  /** Per chunk, index levels included: peer → copies, or null when not audited yet. */
  chunkHolders: { level: number; holders: Record<string, number> | null }[];
}

export interface Holdings {
  quota: number;
  used: number;
  cache: number;
  holds: { author: string; group: string; tier: "committed" | "cache"; blocks: number; bytes: number;
    keepsForUs: number; allowance?: number }[];
  keepsForUs: { group: string; peer: string; bytes: number }[];
}

export interface Probe {
  /** Distinct block ids asked about. */
  asked: number;
  peers: { peer: string; linked: boolean; up: boolean; refused: boolean; rtt: number | null; has: number }[];
  files: { root: string; id: string; chunks: number; healthy: number; short: number; lost: number;
    holders: Record<string, number> }[];
}

const NO_ARG = new Uint8Array(0);
const dec = new TextDecoder();

export class StoreClient {
  constructor(private readonly invoke: Invoke) {}

  /** One op, its argument `parts` back to back, framed in one copy. */
  private op(name: string, ...parts: Uint8Array[]): Promise<Uint8Array> {
    return this.invoke(concatBytes([writeOp(name, NO_ARG), ...parts]));
  }

  private async json<T>(name: string, arg: Uint8Array = NO_ARG): Promise<T> {
    const o = JSON.parse(dec.decode(await this.op(name, arg)));
    if (o?.v !== CLIENT_VERSION) throw new Error(`${name}: answer version ${o?.v}, this client reads ${CLIENT_VERSION}`);
    return o as T;
  }

  async files(): Promise<FileInfo[]> {
    return (await this.json<{ files: FileInfo[] }>(Op.FILES)).files;
  }

  /** Where the ledger saw each chunk: one file by its root descriptor, or every file. */
  async placement(root?: Uint8Array): Promise<FilePlacement[]> {
    return (await this.json<{ files: FilePlacement[] }>(Op.PLACEMENT, root)).files;
  }

  async holdings(): Promise<Holdings> {
    return this.json<Holdings>(Op.HOLDINGS);
  }

  /** Ask the node's roster now which blocks of one file, or of every file, they have. */
  async probe(root?: Uint8Array): Promise<Probe> {
    return this.json<Probe>(Op.PROBE, root);
  }

  /** PUT a file into one of the node's groups (its only one when omitted), streamed in
   *  the windows the guest asks for. A node keeps one PUT stream: a later put on it
   *  replaces this one, which then fails. */
  async put(plaintext: Uint8Array, opts: { group?: string } = {}): Promise<PutResult> {
    const start = await this.op(Op.PUT_START, opts.group ? groupBytes(opts.group) : NO_ARG);
    const windowBytes = readU32BE(start, 0), stream = start.subarray(4, 8);
    for (let off = 0; ; off += windowBytes) {
      await this.op(Op.PUT_WINDOW, stream, plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
      if (off + windowBytes >= plaintext.length) break;
    }
    return decodePutResult(await this.op(Op.PUT_FINISH, stream));
  }

  /** GET a file by its root descriptor and key, streamed. A node keeps one GET stream, as
   *  it does one PUT stream. */
  async get(root: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    const start = await this.op(Op.GET_START, key, root);
    const fileSize = readU64BE(start, 0), stream = start.subarray(8, 12);
    const out = new Uint8Array(fileSize);
    let written = 0;
    while (written < fileSize) {
      const part = await this.op(Op.GET_NEXT, stream);
      if (part.length === 0) throw new Error(`get: stream ended ${written}/${fileSize} bytes in`);
      out.set(part, written); written += part.length;
    }
    return out;
  }
}

export { encodeToken, decodeToken, type FileToken } from "./protocol.js";
