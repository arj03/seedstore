// Minimal test harness shared by all seedstore test modules. No dependencies;
// mirrors the assert/log style of seedkernel's tests/run.mjs.

export function makeT() {
  let passed = 0;
  let failed = 0;
  const failures = [];

  function norm(v) {
    if (v === null || v === undefined) return String(v);
    if (v instanceof Uint8Array || Array.isArray(v)) return JSON.stringify([...v]);
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  const t = {
    group(name) { console.log(`\n— ${name}`); },
    ok(cond, msg) {
      if (cond) { passed++; console.log(`  ok   ${msg}`); }
      else { failed++; failures.push(msg); console.error(`  FAIL ${msg}`); }
    },
    eq(actual, expected, msg) {
      const a = norm(actual), e = norm(expected);
      t.ok(a === e, `${msg}${a === e ? "" : ` (expected ${e}, got ${a})`}`);
    },
    get passed() { return passed; },
    get failed() { return failed; },
    summary() {
      console.log(`\nResults: ${passed} passed, ${failed} failed`);
      return failed;
    },
  };
  return t;
}
