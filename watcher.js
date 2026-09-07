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
};

const ABI = [
  "function attest(address target,uint8 riskScore,uint16 flags,bytes32 reportHash,uint32 schemaVersion)",
  "function attestBatch(address[] targets,uint8[] riskScores,uint16[] flagsArr,bytes32[] reportHashes,uint32 schemaVersion)",
  "function hasAttestation(address) view returns (bool)",
  "function isAttester(address) view returns (bool)",
  "function totalAttestations() view returns (uint256)",
];

const UA = { "User-Agent": "Aegis-Watcher/1.0", Accept: "application/json" };
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
  const d = await getJson(`${CFG.analyzeUrl}?address=${address}`);
  if (!d.ok) throw new Error(d.error || "analyze failed");
  return d;
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
    try {
      if (!(await registry.hasAttestation(c.address))) fresh.push(c);
    } catch (e) { log("  hasAttestation error", c.address, e.message); }
  }
  log(`${fresh.length} not yet attested`);
  if (!fresh.length) return log("nothing to do");

  // analyze
  const rows = [];
  let degraded = 0;
  for (const c of fresh) {
    try {
      const r = await analyze(c.address);
      rows.push({
        address: c.address,
        score: r.score,
        flags: r.flags,
        hash: ethers.keccak256(ethers.toUtf8Bytes(r.report || "{}")),
        engine: r.engine,
        name: r.name || c.name,
      });
      log(`  scanned ${c.address} ${r.name || c.name} -> ${r.score}/100 flags=${r.flags} [${r.engine}]`);
      if (r.verified && r.engine !== "ai+static") {
        degraded++;
        log(`  !! AI LAYER DEGRADED on a verified contract: ${r.aiError || "unknown"}`);
      }
    } catch (e) {
      log(`  scan failed ${c.address}: ${e.message}`);
    }
    await sleep(1200); // be polite to the API + model
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
        2 // schemaVersion 2 = AI+static engine
      );
      log(`  attestBatch(${b.length}) sent ${tx.hash}`);
      await tx.wait();
      log(`  confirmed ${CFG.explorer}/tx/${tx.hash}`);
    } catch (e) {
      log(`  attestBatch failed: ${e.shortMessage || e.message}`);
    }
    await sleep(2000);
  }

  const total = await registry.totalAttestations();
  if (degraded) {
    log(`!! WARNING: ${degraded}/${rows.length} verified contracts fell back to bytecode-only.`);
    log(`!! Check ANTHROPIC_API_KEY and the Console balance — attestations are being written WITHOUT AI findings.`);
  }
  log(`cycle done — totalAttestations = ${total}${degraded ? " (DEGRADED)" : ""}`);

  // append KPI series for the growth chart
  try {
    require("fs").appendFileSync(__dirname + "/kpi.csv",
      `${new Date().toISOString()},${total},${rows.length},${degraded}\n`);
  } catch (e) { log("kpi write failed:", e.message); }
}

async function main() {
  if (!CFG.key) { console.error("ATTESTER_KEY missing (see .env.example)"); process.exit(1); }
  const provider = new ethers.JsonRpcProvider(CFG.rpc);
  const wallet = new ethers.Wallet(CFG.key, provider);
  const registry = new ethers.Contract(CFG.registry, ABI, wallet);

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
