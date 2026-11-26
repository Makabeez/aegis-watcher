#!/usr/bin/env node
/**
 * clone-scout.js — score unverified clones of templates Aegis has already reviewed.
 *
 * The watcher only sees verified contracts. Launchpad tokens are mostly unverified clones of one
 * template, and that is where launch-day rugs come from. Every cycle this process:
 *   1. reads ERC-20/721 mint events (Transfer from 0x0) since the last block it saw — every new
 *      token mints in its constructor, so this finds newly deployed tokens, factory-made ones too;
 *   2. computes each new contract's template key (templates.js: metadata stripped, PUSH32 masked,
 *      minimal proxies resolved);
 *   3. if that template already has a verdict (from a full AI scan of a verified sibling, or a
 *      hand review), writes the same score and flags for the clone, schema 5 ("template match");
 *   4. otherwise counts the unknown template and flags popular ones (10 / 50 / 200 clones) so a
 *      human can review or ask the deployer to verify.
 *
 * Use its OWN attester key (CLONE_ATTESTER_KEY), not the watcher's: two processes sharing a key
 * would fight over nonces. The registry owner enables it once with setAttester(addr, true).
 *
 *   node clone-scout.js            run forever (SCOUT_INTERVAL_MS, default 120 s)
 *   RUN_ONCE=1 DRY_RUN=1 node clone-scout.js   one cycle, write nothing on-chain
 */
require("dotenv").config();
const fs = require("fs");
const { ethers } = require("ethers");
const { templateKey, TemplateStore } = require("./templates");

const CFG = {
  rpc:        process.env.GIWA_RPC      || "https://sepolia-rpc.giwa.io",
  explorer:   process.env.GIWA_EXPLORER || "https://sepolia-explorer.giwa.io",
  registry:   process.env.SCAN_REGISTRY || "0x6C831F9d7051E94589807D2C3d924bb195b5de94",
  key:        process.env.CLONE_ATTESTER_KEY,
  intervalMs: parseInt(process.env.SCOUT_INTERVAL_MS || "120000", 10),
  span:       parseInt(process.env.SCOUT_LOG_SPAN || "2000", 10),       // blocks per eth_getLogs
  backfill:   parseInt(process.env.SCOUT_BACKFILL || "20000", 10),      // blocks to look back on first start
  maxNew:     parseInt(process.env.SCOUT_MAX_NEW || "400", 10),          // new contracts inspected per cycle
  maxAttest:  parseInt(process.env.SCOUT_MAX_ATTEST || "100", 10),       // attestations written per cycle
  batchSize:  parseInt(process.env.BATCH_SIZE || "20", 10),
  minBalance: process.env.MIN_BALANCE_ETH || "0.002",
  once:       process.env.RUN_ONCE === "1",
  dryRun:     process.env.DRY_RUN === "1",
};
const SCHEMA_TEMPLATE_MATCH = 5;
const TRANSFER = ethers.id("Transfer(address,address,uint256)");
const ZERO_TOPIC = ethers.zeroPadValue("0x", 32);
const ABI = [
  "function attestBatch(address[] targets,uint8[] riskScores,uint16[] flagsArr,bytes32[] reportHashes,uint32 schemaVersion)",
  "function hasAttestation(address) view returns (bool)",
  "function isAttester(address) view returns (bool)",
];
const STATE_FILE = __dirname + "/clone-scout.state.json";
const UNKNOWN_FILE = __dirname + "/unknown-templates.json";
const REPORT_DIR = __dirname + "/template-reports";
const MAX_SEEN = 500_000;

const log = (...a) => console.log(new Date().toISOString(), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (_) { return d; } };
const writeJson = (f, v) => { try { fs.writeFileSync(f, JSON.stringify(v)); } catch (e) { log("write failed", f, e.message); } };

async function retry(fn, tries = 4) {
  for (let a = 0; ; a++) {
    try { return await fn(); } catch (e) { if (a >= tries - 1) throw e; await sleep(1500 * (a + 1)); }
  }
}

async function telegram(text) {
  const t = process.env.TELEGRAM_BOT_TOKEN, c = process.env.TELEGRAM_CHAT_ID;
  if (!t || !c) return;
  try {
    await fetch(`https://api.telegram.org/bot${t}/sendMessage`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: c, text, disable_web_page_preview: true }),
    });
  } catch (_) {}
}

/** The report a template-match attestation commits to. Saved locally; its keccak is the reportHash. */
function matchReport(target, key, verdict) {
  const report = {
    kind: "aegis-template-match", schema: SCHEMA_TEMPLATE_MATCH, target, templateKey: key,
    inheritedFrom: verdict.source, inheritedReportHash: verdict.reportHash,
    score: verdict.score, flags: verdict.flags,
    method: "runtime bytecode with CBOR metadata stripped and PUSH32 operands zeroed; minimal proxies resolved to their implementation",
    limitation: "contracts differing only in 32-byte constants share a template; this is a template verdict, not an individual audit",
  };
  const text = JSON.stringify(report);
  try { fs.mkdirSync(REPORT_DIR, { recursive: true }); fs.writeFileSync(`${REPORT_DIR}/${target.toLowerCase()}.json`, text); } catch (_) {}
  return ethers.keccak256(ethers.toUtf8Bytes(text));
}

async function cycle(provider, registry, store, state, unknown) {
  const head = await retry(() => provider.getBlockNumber());
  let from = state.lastBlock ? state.lastBlock + 1 : Math.max(0, head - CFG.backfill);
  if (from > head) return log("no new blocks");

  // 1. discover new token contracts from mint events
  const fresh = [];
  let scannedTo = from - 1;
  while (from <= head && fresh.length < CFG.maxNew) {
    const to = Math.min(head, from + CFG.span - 1);
    const logs = await retry(() => provider.getLogs({ fromBlock: from, toBlock: to, topics: [TRANSFER, ZERO_TOPIC] }));
    for (const l of logs) {
      const a = l.address.toLowerCase();
      if (state.seen[a]) continue;
      state.seen[a] = 1;
      fresh.push(l.address);
    }
    scannedTo = to;
    from = to + 1;
  }
  state.lastBlock = scannedTo;
  log(`blocks ..${scannedTo} (head ${head}): ${fresh.length} new token contracts`);

  // 2-3. template lookup
  const implCache = new Map();
  const getCode = async (a) => {
    const k = a.toLowerCase();
    if (implCache.has(k)) return implCache.get(k);
    const c = await retry(() => provider.getCode(a));
    implCache.set(k, c);
    return c;
  };
  const matches = [];
  let unknownCount = 0;
  // read code 12 at a time: thousands of new tokens per hour is normal on a busy testnet
  const keys = [];
  for (let i = 0; i < fresh.length; i += 12) {
    const part = fresh.slice(i, i + 12);
    const got = await Promise.all(part.map((a) => templateKey(provider, a, getCode).catch((e) => { log(`  code read failed ${a}: ${e.message}`); return null; })));
    part.forEach((a, j) => keys.push([a, got[j]]));
  }
  for (const [addr, t] of keys) {
    if (!t) continue;
    const verdict = store.get(t.key);
    if (verdict) { matches.push({ addr, key: t.key, verdict }); continue; }
    unknownCount++;
    const u = (unknown[t.key] ||= { count: 0, samples: [], firstSeen: new Date().toISOString(), impl: t.impl, size: t.size });
    u.count++;
    if (u.samples.length < 5) u.samples.push(addr);
    for (const level of [10, 50, 200]) {
      if (u.count === level) {
        const msg = `Aegis: unscored template now has ${level} clones (key ${t.key.slice(0, 18)}…, ${t.size} bytes${t.impl ? `, proxy to ${t.impl}` : ""}). Samples: ${u.samples.slice(0, 3).join(", ")}. Review it or ask the deployer to verify.`;
        log("!! " + msg);
        await telegram(msg);
      }
    }
  }
  log(`  ${matches.length} match a known template, ${unknownCount} unknown (${Object.keys(unknown).length} unknown templates tracked)`);

  // skip clones already in the registry
  const todo = [];
  for (let i = 0; i < matches.length && todo.length < CFG.maxAttest; i += 12) {
    const part = matches.slice(i, i + 12);
    const has = await Promise.all(part.map((m) => retry(() => registry.hasAttestation(m.addr)).catch(() => true)));
    part.forEach((m, j) => { if (!has[j] && todo.length < CFG.maxAttest) todo.push(m); });
  }
  for (const m of todo) log(`  match   ${m.addr} -> ${m.verdict.score}/100 flags=${m.verdict.flags} via ${m.verdict.source} (${m.verdict.name})`);
  if (!todo.length) return;
  if (CFG.dryRun) return log(`DRY_RUN: would attest ${todo.length} clones`);

  // write in batches
  for (let i = 0; i < todo.length; i += CFG.batchSize) {
    const b = todo.slice(i, i + CFG.batchSize);
    try {
      const tx = await registry.attestBatch(
        b.map((m) => m.addr), b.map((m) => m.verdict.score), b.map((m) => m.verdict.flags),
        b.map((m) => matchReport(m.addr, m.key, m.verdict)), SCHEMA_TEMPLATE_MATCH);
      log(`  attestBatch(${b.length}) ${tx.hash}`);
      await tx.wait();
    } catch (e) {
      log(`  attestBatch failed: ${e.shortMessage || e.message}`);
      try { registry.runner.reset(); } catch (_) {}
      for (const m of b) delete state.seen[m.addr.toLowerCase()];   // retry them next cycle
      await sleep(5000);
    }
  }
}

async function main() {
  const provider = new ethers.JsonRpcProvider(CFG.rpc);
  let registry;
  if (CFG.dryRun) {
    registry = new ethers.Contract(CFG.registry, ABI, provider);
  } else {
    if (!CFG.key) { console.error("CLONE_ATTESTER_KEY missing (use a separate key from the watcher)"); process.exit(1); }
    const wallet = new ethers.Wallet(CFG.key, provider);
    registry = new ethers.Contract(CFG.registry, ABI, new ethers.NonceManager(wallet));
    if (!(await registry.isAttester(wallet.address))) {
      console.error(`${wallet.address} is not an attester. Owner: setAttester("${wallet.address}", true)`);
      process.exit(1);
    }
    log("clone attester:", wallet.address);
  }
  log(`clone-scout on ${CFG.rpc}, registry ${CFG.registry}${CFG.dryRun ? " (DRY RUN)" : ""}`);

  while (true) {
    const store = new TemplateStore(__dirname + "/templates.json");   // reloaded: the watcher adds to it
    const state = readJson(STATE_FILE, { lastBlock: 0, seen: {} });
    const unknown = readJson(UNKNOWN_FILE, {});
    try {
      if (!CFG.dryRun) {
        const bal = await provider.getBalance(await registry.runner.getAddress());
        if (bal < ethers.parseEther(CFG.minBalance)) { log(`!! clone attester balance ${ethers.formatEther(bal)} ETH below ${CFG.minBalance}`); }
        else await cycle(provider, registry, store, state, unknown);
      } else await cycle(provider, registry, store, state, unknown);
    } catch (e) { log("cycle error:", e.message); }
    const keys = Object.keys(state.seen);
    if (keys.length > MAX_SEEN) for (const k of keys.slice(0, keys.length - MAX_SEEN)) delete state.seen[k];
    if (!CFG.dryRun || !CFG.once) { writeJson(STATE_FILE, state); writeJson(UNKNOWN_FILE, unknown); }
    log(`templates known: ${store.size()}`);
    if (CFG.once) break;
    await sleep(CFG.intervalMs);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
