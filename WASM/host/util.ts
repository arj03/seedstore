// Small byte helpers shared across the storage host. No dependencies.

const HEX_CHARS = "0123456789abcdef";
export function toHex(b: Uint8Array): string {
  const chars: string[] = new Array(b.length * 2);
  for (let i = 0; i < b.length; i++) {
    const h = b[i];
    chars[i * 2] = HEX_CHARS[(h >> 4) & 0xf];
    chars[i * 2 + 1] = HEX_CHARS[h & 0xf];
  }
  return chars.join("");
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function writeU32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

export function readU32BE(buf: Uint8Array, offset: number): number {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) |
          (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

/** Map `fn` over `items` with at most `width` tasks in flight, returning results
 *  by input index (order preserved regardless of completion order). A bounded
 *  worker pool: `width` workers each pull the next unclaimed index until the list
 *  drains, so a slow item never stalls the others and never more than `width`
 *  requests are outstanding at once. `width <= 1` runs strictly serially. */
export async function mapPool<T, R>(
  items: readonly T[], width: number, fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Math.max(1, Math.min(Math.floor(width) || 1, items.length));
  const run = async (): Promise<void> => {
    for (let i = next++; i < items.length; i = next++) out[i] = await fn(items[i], i);
  };
  await Promise.all(Array.from({ length: workers }, run));
  return out;
}
