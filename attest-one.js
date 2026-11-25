#!/usr/bin/env node
/**
 * attest-one.js — score specific GIWA contracts on demand and write them to ScanRegistry.
 *
 * For contracts the hourly watcher never sees (verified before its window), e.g. a
 * partner's older contract. Uses the same .env as watcher.js (GIWA_RPC, ATTESTER_KEY,
 * AEGIS_INTERNAL_KEY, ANALYZE_URL, SCAN_REGISTRY).
 *
 *   node attest-one.js 0xAddr [0xAddr2 ...]          dry run: scans, prints, writes nothing
 *   node attest-one.js 0xAddr [0xAddr2 ...] --send   writes one attestBatch (schema v4)
 *
 * Blast radius: one testnet tx, a few addresses get a new latest score. Max 20 addresses.
 * Refuses to write a result that did not come from the full AI + static engine.
 * The key is read from .env and never printed.
 */
require("dotenv").config();
const { ethers } = require("ethers");

const RPC = process.env.GIWA_RPC || "https://sepolia-rpc.giwa.io";
const REGISTRY = process.env.SCAN_REGISTRY || "0x6C831F9d7051E94589807D2C3d924bb195b5de94";
const ANALYZE = process.env.ANALYZE_URL || "https://aegis-giwa-makabeezs-projects.vercel.app/api/analyze";
const KEY = process.env.AEGIS_INTERNAL_KEY || "";
const SCHEMA = 4;
const ABI = [
  "function attestBatch(address[] targets,uint8[] riskScores,uint16[] flagsArr,bytes32[] reportHashes,uint32 schemaVersion)",
  "function isAttester(address) view returns (bool)",
  "function hasAttestation(address) view returns (bool)",
  "function getAttestation(address) view returns (tuple(uint8 riskScore,uint16 flags,bytes32 reportHash,uint64 timestamp,address attester,uint32 schemaVersion))",
];

const send = process.argv.includes("--send");
const addrs = process.argv.slice(2).filter((a) => a !== "--send");

(async () => {
  if (!addrs.length) { console.error("usage: node attest-one.js 0xAddr [0xAddr2 ...] [--send]"); process.exit(1); }
  if (addrs.length > 20) { console.error("max 20 addresses per run"); process.exit(1); }
  for (const a of addrs) if (!ethers.isAddress(a)) { console.error(`bad address: ${a}`); process.exit(1); }
  if (!process.env.ATTESTER_KEY) { console.error("ATTESTER_KEY missing in .env"); process.exit(1); }

  const provider = new ethers.JsonRpcProvider(RPC);
  const net = await provider.getNetwork();
  if (net.chainId !== 91342n) { console.error(`wrong chain ${net.chainId}, expected 91342`); process.exit(1); }
  const wallet = new ethers.Wallet(process.env.ATTESTER_KEY, provider);
  const registry = new ethers.Contract(REGISTRY, ABI, wallet);
  if (!(await registry.isAttester(wallet.address))) { console.error(`${wallet.address} is not an attester`); process.exit(1); }

  const rows = [];
  for (const a of addrs) {
    const headers = KEY ? { "x-aegis-key": KEY } : {};
    const r = await fetch(`${ANALYZE}?address=${a}`, { headers, signal: AbortSignal.timeout(120000) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok || !d.ok) { console.error(`${a}: analyze failed (${r.status}) ${d.error || ""}`); process.exit(1); }
    if (d.engine !== "ai+static") { console.error(`${a}: engine was "${d.engine}", not ai+static. Not writing a degraded score.`); process.exit(1); }
    const prev = (await registry.hasAttestation(a)) ? `${(await registry.getAttestation(a)).riskScore}/100` : "none";
    console.log(`${a}  ${d.name || ""}  -> ${d.score}/100 flags=${d.flags}  (on-chain now: ${prev})`);
    for (const f of d.findings || []) console.log(`   - [${f.severity}/${f.source}] ${f.title}`);
    rows.push({ a, score: d.score, flags: d.flags, hash: ethers.keccak256(ethers.toUtf8Bytes(d.report || "{}")) });
  }

  if (!send) { console.log("DRY RUN — nothing written. Re-run with --send to write."); return; }

  const tx = await registry.attestBatch(rows.map((r) => r.a), rows.map((r) => r.score),
    rows.map((r) => r.flags), rows.map((r) => r.hash), SCHEMA);
  console.log(`sent ${tx.hash}`);
  const rc = await tx.wait();
  if (rc.status !== 1) { console.error("reverted"); process.exit(1); }
  console.log(`confirmed https://sepolia-explorer.giwa.io/tx/${tx.hash}`);
})().catch((e) => { console.error(e.shortMessage || e.message); process.exit(1); });
