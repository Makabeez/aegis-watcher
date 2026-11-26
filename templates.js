/**
 * templates.js — recognise contracts built from the same code template.
 *
 * Launchpads deploy hundreds of tokens from one template, usually unverified. Their runtime
 * bytecode is NOT identical: every token bakes its own immutables (pair address, launchpad,
 * supply…) into the code, and the compiler appends a metadata hash. So an exact code hash
 * never matches. A "template hash" does:
 *   1. strip the trailing CBOR metadata section,
 *   2. zero every PUSH32 operand (immutables and 32-byte constants live there),
 *   3. keccak256 what is left.
 * Minimal proxies (EIP-1167, its PUSH0 variant, Solady LibClone) resolve to their implementation.
 *
 * Known limitation, stated in every template attestation's report: two contracts that differ
 * only in 32-byte constants share a template hash. PUSH1..PUSH31 operands (including PUSH20
 * hard-coded addresses) are kept, so a variant that hard-codes a different fee wallet or
 * router does NOT match.
 */
const fs = require("fs");
const { ethers } = require("ethers");

// Minimal proxies: EIP-1167 (45 bytes), its PUSH0 variant, and Solady's LibClone (44 bytes) all
// end in PUSH20 <implementation> GAS DELEGATECALL. Only short code (< 100 bytes) qualifies.
const PROXY_RE = /73([0-9a-f]{40})5af4/i;

/** Returns the implementation address if `code` is a minimal proxy, else null. */
function minimalProxyTarget(code) {
  const c = (code || "").toLowerCase();
  if (c.length < 4 || (c.length - 2) / 2 >= 100) return null;
  const m = c.match(PROXY_RE);
  return m ? ethers.getAddress("0x" + m[1]) : null;
}

/** Byte length of the trailing Solidity CBOR metadata (incl. its 2-byte length), or 0. */
function metadataLength(bytes) {
  if (bytes.length < 4) return 0;
  const len = (bytes[bytes.length - 2] << 8) | bytes[bytes.length - 1];
  if (len === 0 || len > 256 || len + 2 > bytes.length) return 0;
  const first = bytes[bytes.length - 2 - len];
  // CBOR map with 1..6 entries (0xa1..0xa6) is what solc and vyper emit
  return first >= 0xa1 && first <= 0xa6 ? len + 2 : 0;
}

/** Template hash of runtime bytecode (hex string with 0x). Empty code returns null. */
function templateHash(code) {
  if (!code || code === "0x") return null;
  const bytes = ethers.getBytes(code);
  const end = bytes.length - metadataLength(bytes);
  const out = Uint8Array.from(bytes.subarray(0, end));
  for (let i = 0; i < end; i++) {
    const op = out[i];
    if (op >= 0x60 && op <= 0x7f) {            // PUSH1..PUSH32
      const n = op - 0x5f;
      if (n === 32) out.fill(0, i + 1, Math.min(i + 1 + n, end));
      i += n;
    }
  }
  return ethers.keccak256(out);
}

/**
 * Template key for an address: resolves minimal proxies one level, so every clone of the same
 * implementation shares a key ("proxy:" + implementation's template hash).
 */
async function templateKey(provider, address, getCode = (a) => provider.getCode(a)) {
  const code = await getCode(address);
  const impl = minimalProxyTarget(code);
  if (impl) {
    const implHash = templateHash(await getCode(impl));
    return implHash ? { key: "proxy:" + implHash, impl, size: (code.length - 2) / 2 } : null;
  }
  const h = templateHash(code);
  return h ? { key: h, impl: null, size: (code.length - 2) / 2 } : null;
}

/** Small JSON-file store: template key -> verdict learned from a full scan or a hand review. */
class TemplateStore {
  constructor(file) {
    this.file = file;
    try { this.db = JSON.parse(fs.readFileSync(file, "utf8")); } catch (_) { this.db = {}; }
  }
  get(key) { return this.db[key] || null; }
  /** Record a verdict. `source` says where it came from: "scan:<addr>" or "review:<file>". */
  learn(key, { score, flags, reportHash, source, name }) {
    if (!key) return;
    // re-read first: the watcher, clone-scout and learn-templates.js share this file
    try { this.db = JSON.parse(fs.readFileSync(this.file, "utf8")); } catch (_) {}
    const prev = this.db[key];
    // a hand review always wins over an automated scan; otherwise keep the first verdict
    if (prev && !(source.startsWith("review:") && !prev.source.startsWith("review:"))) return;
    this.db[key] = { score, flags, reportHash, source, name: name || "?", learnedAt: new Date().toISOString() };
    this.save();
  }
  save() { try { fs.writeFileSync(this.file, JSON.stringify(this.db, null, 1)); } catch (_) {} }
  size() { return Object.keys(this.db).length; }
}

module.exports = { templateHash, templateKey, minimalProxyTarget, metadataLength, TemplateStore };
