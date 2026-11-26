#!/usr/bin/env node
/**
 * Aegis watcher — continuously scans newly verified contracts on GIWA and
 * writes risk attestations on-chain to ScanRegistry.
 *
 * Design notes:
 *  - Analysis is delegated to the live /api/analyze endpoint, so there is ONE
 *    engine and no Anthropic key is needed on this machine.
 *  - Dedupe is done on-chain via hasAttestation(), so the script is stateless
 *    and safe to restart / run on multiple boxes.
 *  - Writes are batched with attestBatch() to save gas and tx count.
 *  - The attester wallet should be a DEDICATED throwaway key holding only
 *    testnet gas. Blast radius if leaked: someone can write junk attestations
 *    and drain that wallet's testnet gas. It cannot touch your main funds,
 *    and the owner can revoke it with setAttester(addr,false).
 */

require("dotenv").config();
const { ethers } = require("ethers");

const CFG = {
  rpc:        process.env.GIWA_RPC        || "https://sepolia-rpc.giwa.io",
  explorer:   process.env.GIWA_EXPLORER   || "https://sepolia-explorer.giwa.io",
  registry:   process.env.SCAN_REGISTRY   || "0x6C831F9d7051E94589807D2C3d924bb195b5de94",
  analyzeUrl: process.env.ANALYZE_URL     || "https://aegis-giwa-makabeezs-projects.vercel.app/api/analyze",
  key:        process.env.ATTESTER_KEY,
  pages:      parseInt(process.env.PAGES_PER_RUN || "2", 10),   // 50 contracts per page
  maxPerRun:  parseInt(process.env.MAX_PER_RUN   || "25", 10),  // cap attestations per cycle
  batchSize:  parseInt(process.env.BATCH_SIZE    || "10", 10),
  intervalMs: parseInt(process.env.INTERVAL_MS   || "3600000", 10), // 1h
  minBalance: process.env.MIN_BALANCE_ETH || "0.005",
  once:       process.env.RUN_ONCE === "1",
  dryRun:     process.env.DRY_RUN === "1",
  maxAiPerDay: parseInt(process.env.MAX_AI_PER_DAY || "0", 10),       // 0 = no cap (Sepolia default)
};

const ABI = [
  "function attest(address target,uint8 riskScore,uint16 flags,bytes32 reportHash,uint32 schemaVersion)",
  "function attestBatch(address[] targets,uint8[] riskScores,uint16[] flagsArr,bytes32[] reportHashes,uint32 schemaVersion)",
  "function hasAttestation(address) view returns (bool)",
  "function isAttester(address) view returns (bool)",
  "function totalAttestations() view returns (uint256)",
];

const UA = { "User-Agent": "Aegis-Watcher/1.0", Accept: "application/json" };
const INTERNAL_KEY = process.env.AEGIS_INTERNAL_KEY || "";
const fs = require("fs");
const CACHE_FILE = __dirname + "/bytecode-cache.json";
let codeCache = {};
try { codeCache = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8")); } catch (_) {}
const COVERAGE_FILE = __dirname + "/.coverage-day";
async function countVerified() {
  // Pages until exhausted. GIWA Sepolia has tens of thousands of verified
  // contracts, so this is slow — run it weekly, not per cycle. Returns a
  // completeness flag so a page cap is never reported as if it were the truth.
  const MAX_PAGES = 1200;                 // 60k contracts
  let total = 0, params = null, pages = 0;
  while (pages < MAX_PAGES) {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    let d;
    try { d = await getJson(`${CFG.explorer}/api/v2/smart-contracts${qs}`); }
    catch (e) { return { total, complete: false, error: e.message }; }
    const n = (d.items || []).length;
    total += n; pages++;
    params = d.next_page_params;
    if (!params || !n) return { total, complete: true };
    await sleep(120);
  }
  return { total, complete: false };
}

const saveCache = () => { try { fs.writeFileSync(CACHE_FILE, JSON.stringify(codeCache)); } catch (_) {} };

// template verdicts shared with clone-scout.js (see templates.js)
const { templateKey, TemplateStore } = require("./templates");
const templates = new TemplateStore(__dirname + "/templates.json");
let CHAIN_ID = "?";   // set in main() from the RPC

// daily cap on AI scans, so a flood of new deployments (mainnet launch day) can't run up the bill
const AI_DAY_FILE = __dirname + "/.ai-day.json";
const today = () => new Date().toISOString().slice(0, 10);
function aiBudgetLeft() {
  if (!CFG.maxAiPerDay) return true;
  let d = {}; try { d = JSON.parse(fs.readFileSync(AI_DAY_FILE, "utf8")); } catch (_) {}
  return d.day !== today() || (d.n || 0) < CFG.maxAiPerDay;
}
function aiUsed() {
  let d = {}; try { d = JSON.parse(fs.readFileSync(AI_DAY_FILE, "utf8")); } catch (_) {}
  if (d.day !== today()) d = { day: today(), n: 0 };
  d.n++;
  try { fs.writeFileSync(AI_DAY_FILE, JSON.stringify(d)); } catch (_) {}
}

const log = (...a) => console.log(new Date().toISOString(), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(url) {
  const r = await fetch(url, { headers: UA });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}

/** Page through Blockscout's verified-contract list (newest first). */
async function listVerified(pages) {
  const out = [];
  let params = null;
  for (let i = 0; i < pages; i++) {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    const d = await getJson(`${CFG.explorer}/api/v2/smart-contracts${qs}`);
    for (const it of d.items || []) {
      const a = it.address || {};
      if (a.hash) out.push({ address: a.hash, name: a.name || it.name || "?" });
    }
    params = d.next_page_params;
    if (!params) break;
    await sleep(300);
  }
  // de-dup within the batch, preserve order
  const seen = new Set();
  return out.filter((c) => !seen.has(c.address.toLowerCase()) && seen.add(c.address.toLowerCase()));
}

async function analyze(address) {
  const headers = INTERNAL_KEY ? { ...UA, "x-aegis-key": INTERNAL_KEY } : UA;
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await fetch(`${CFG.analyzeUrl}?address=${address}`, { headers });
    if (r.status === 429) { await sleep(8000 * (attempt + 1)); continue; }   // backoff on rate limit
    if (!r.ok) throw new Error(`${r.status}`);
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || "analyze failed");
    return d;
  }
  throw new Error("rate limited after retries");
}

async function cycle(provider, wallet, registry) {
  log("cycle start");

  const bal = await provider.getBalance(wallet.address);
  if (bal < ethers.parseEther(CFG.minBalance)) {
    log(`!! attester balance ${ethers.formatEther(bal)} ETH below ${CFG.minBalance} — top up ${wallet.address}`);
    return;
  }

  const candidates = await listVerified(CFG.pages);
  log(`fetched ${candidates.length} verified contracts`);

  // on-chain dedupe
  const fresh = [];
  for (const c of candidates) {
    if (fresh.length >= CFG.maxPerRun) break;
    let ok = false;
    for (let a = 0; a < 3 && !ok; a++) {
      try {
        if (!(await registry.hasAttestation(c.address))) fresh.push(c);
        ok = true;
      } catch (e) {
        if (a === 2) log(`  hasAttestation failed (${c.address}): RPC error, skipping this cycle`);
        else await sleep(800 * (a + 1));
      }
    }
  }
  log(`${fresh.length} not yet attested`);
  if (!fresh.length) return log("nothing to do");

  // analyze
  const rows = [];
  let degraded = 0;
  for (const c of fresh) {
    try {
      // identical bytecode => identical verdict. Saves AI spend and makes
      // duplicate template contracts deterministic.
      let code = null;
      for (let a = 0; a < 4 && code === null; a++) {
        try { code = await provider.getCode(c.address); }
        catch (err) { if (a === 3) throw err; await sleep(1500 * (a + 1)); }
      }
      const codeHash = ethers.keccak256(code);
      const cached = codeCache[codeHash];
      if (cached) {
        rows.push({ address: c.address, score: cached.score, flags: cached.flags,
                    hash: cached.hash, engine: "cached", name: c.name });
        log(`  cached  ${c.address} ${c.name} -> ${cached.score}/100 flags=${cached.flags} [bytecode-match]`);
        continue;
      }
      if (!aiBudgetLeft()) {
        log(`  !! daily AI budget reached (MAX_AI_PER_DAY=${CFG.maxAiPerDay}) — ${c.address} waits for tomorrow`);
        break;
      }
      const r = await analyze(c.address);
      aiUsed();
      rows.push({
        address: c.address,
        score: r.score,
        flags: r.flags,
        hash: ethers.keccak256(ethers.toUtf8Bytes(r.report || "{}")),
        engine: r.engine,
        name: r.name || c.name,
      });
      log(`  scanned ${c.address} ${r.name || c.name} -> ${r.score}/100 flags=${r.flags} [${r.engine}]`);
      if (r.engine === "ai+static") {
        codeCache[codeHash] = { score: r.score, flags: r.flags,
          hash: ethers.keccak256(ethers.toUtf8Bytes(r.report || "{}")) };
        saveCache();
        // teach clone-scout: unverified clones of this template inherit this verdict
        try {
          const t = await templateKey(provider, c.address, async (a) => (a.toLowerCase() === c.address.toLowerCase() ? code : provider.getCode(a)));
          if (t) templates.learn(t.key, { score: r.score, flags: r.flags, reportHash: codeCache[codeHash].hash,
                                          source: `scan:${CHAIN_ID}:${c.address}`, name: r.name || c.name });
        } catch (_) {}
      }
      if (r.verified && r.engine !== "ai+static") {
        degraded++;
        log(`  !! AI LAYER DEGRADED on a verified contract: ${r.aiError || "unknown"}`);
      }
    } catch (e) {
      log(`  scan failed ${c.address}: ${e.message}`);
    }
    await sleep(1200); // only reached on a real API call
  }
  if (!rows.length) return log("no successful scans");

  if (CFG.dryRun) return log(`DRY_RUN: would attest ${rows.length} contracts`);

  // batch attest
  for (let i = 0; i < rows.length; i += CFG.batchSize) {
    const b = rows.slice(i, i + CFG.batchSize);
    try {
      const tx = await registry.attestBatch(
        b.map((x) => x.address),
        b.map((x) => x.score),
        b.map((x) => x.flags),
        b.map((x) => x.hash),
        4 // schemaVersion 4 = metadata-safe bytecode heuristics
      );
      log(`  attestBatch(${b.length}) sent ${tx.hash}`);
      await tx.wait();
      log(`  confirmed ${CFG.explorer}/tx/${tx.hash}`);
    } catch (e) {
      log(`  attestBatch failed: ${e.shortMessage || e.message}`);
      try { registry.runner.reset(); } catch (_) {}   // resync nonce after a failure
      await sleep(6000);
    }
    await sleep(2000);
  }

  const total = await registry.totalAttestations();
  if (degraded) {
    log(`!! WARNING: ${degraded}/${rows.length} verified contracts fell back to bytecode-only.`);
    log(`!! Check ANTHROPIC_API_KEY and the Console balance — attestations are being written WITHOUT AI findings.`);
  }
  log(`cycle done — totalAttestations = ${total}${degraded ? " (DEGRADED)" : ""}`);

  // coverage denominator: count verified contracts at most once a day
  let verified = "";
  try {
    const now = Date.now();
    let last = 0;
    try { last = Number(fs.readFileSync(COVERAGE_FILE, "utf8").trim()) || 0; } catch (_) {}
    if (now - last > 7 * 24 * 3600 * 1000) {          // weekly: the count is expensive
      const c = await countVerified();
      fs.writeFileSync(COVERAGE_FILE, String(now));
      verified = c.complete ? String(c.total) : `>=${c.total}`;
      const pct = ((Number(total) / c.total) * 100).toFixed(1);
      log(c.complete
        ? `coverage: ${total}/${c.total} verified contracts (${pct}%)`
        : `coverage: ${total}/>=${c.total} verified contracts (<=${pct}% — count incomplete, treat as an upper bound)`);
    }
  } catch (e) { log("coverage count failed:", e.message); }

  // append KPI series for the growth chart
  try {
    fs.appendFileSync(__dirname + "/kpi.csv",
      `${new Date().toISOString()},${total},${rows.length},${degraded},${verified}\n`);
  } catch (e) { log("kpi write failed:", e.message); }
}

async function main() {
  if (!CFG.key) { console.error("ATTESTER_KEY missing (see .env.example)"); process.exit(1); }
  const provider = new ethers.JsonRpcProvider(CFG.rpc);
  const wallet = new ethers.Wallet(CFG.key, provider);
  const signer = new ethers.NonceManager(wallet);   // local nonce tracking; the RPC's "pending" lags
  const registry = new ethers.Contract(CFG.registry, ABI, signer);
  CHAIN_ID = String((await provider.getNetwork()).chainId);

  log("Aegis watcher starting");
  log("  attester :", wallet.address);
  log("  registry :", CFG.registry);
  log("  analyze  :", CFG.analyzeUrl);

  if (!(await registry.isAttester(wallet.address))) {
    console.error(`\n!! ${wallet.address} is NOT an authorized attester.`);
    console.error(`   Owner must call setAttester("${wallet.address}", true) on the registry first.\n`);
    process.exit(1);
  }

  while (true) {
    try { await cycle(provider, wallet, registry); }
    catch (e) { log("cycle error:", e.message); }
    if (CFG.once) break;
    log(`sleeping ${Math.round(CFG.intervalMs / 60000)}m`);
    await sleep(CFG.intervalMs);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
