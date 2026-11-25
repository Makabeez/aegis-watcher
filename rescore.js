#!/usr/bin/env node
/**
 * Aegis rescore — writes corrected risk scores (schema v4) to ScanRegistry.
 *
 * Input: a corrections JSON produced off-machine:
 *   [{ "address": "0x..", "score": 15, "flags": 12, "report": "<report json string>" }, ...]
 *
 * Default is a DRY RUN: prints what it would write and touches nothing.
 * Add --send to write. Progress is saved after every confirmed batch, so a
 * re-run resumes where it stopped and never double-writes a finished batch.
 *
 * Blast radius: only the listed addresses get a new latest score on the
 * testnet registry. Gas is testnet ETH (~0.0000018 per 20-row batch).
 * The key is read from .env and never printed.
 */
require("dotenv").config();
const fs = require("fs");
const { ethers } = require("ethers");

const RPC = process.env.GIWA_RPC || "https://sepolia-rpc.giwa.io";
const REGISTRY = process.env.SCAN_REGISTRY || "0x6C831F9d7051E94589807D2C3d924bb195b5de94";
const SCHEMA = 4;
const BATCH = 20;
const MAX_ROWS = 5000;
const ABI = [
  "function attestBatch(address[] targets,uint8[] riskScores,uint16[] flagsArr,bytes32[] reportHashes,uint32 schemaVersion)",
  "function isAttester(address) view returns (bool)",
  "function totalAttestations() view returns (uint256)",
];

const file = process.argv[2];
const send = process.argv.includes("--send");
if (!file) { console.error("usage: node rescore.js corrections.json [--send]"); process.exit(1); }
if (!process.env.ATTESTER_KEY) { console.error("ATTESTER_KEY missing in .env"); process.exit(1); }

const rows = JSON.parse(fs.readFileSync(file, "utf8"));
const PROGRESS = file.replace(/\.json$/, "") + ".progress.json";
let done = [];
try { done = JSON.parse(fs.readFileSync(PROGRESS, "utf8")); } catch (_) {}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function validate(r, i) {
  if (!ethers.isAddress(r.address)) throw new Error(`row ${i}: bad address`);
  if (!Number.isInteger(r.score) || r.score < 0 || r.score > 100) throw new Error(`row ${i}: bad score`);
  if (!Number.isInteger(r.flags) || r.flags < 0 || r.flags > 65535) throw new Error(`row ${i}: bad flags`);
  if (typeof r.report !== "string") throw new Error(`row ${i}: missing report`);
}

(async () => {
  rows.forEach(validate);
  if (rows.length > MAX_ROWS) { console.error(`refusing: ${rows.length} rows > ${MAX_ROWS}`); process.exit(1); }

  const provider = new ethers.JsonRpcProvider(RPC);
  const net = await provider.getNetwork();
  if (net.chainId !== 91342n) { console.error(`wrong chain ${net.chainId}, expected 91342`); process.exit(1); }
  const wallet = new ethers.NonceManager(new ethers.Wallet(process.env.ATTESTER_KEY, provider));
  const addr = await wallet.getAddress();
  const registry = new ethers.Contract(REGISTRY, ABI, wallet);
  if (!(await registry.isAttester(addr))) { console.error(`${addr} is not an attester`); process.exit(1); }

  const batches = [];
  for (let i = 0; i < rows.length; i += BATCH) batches.push(rows.slice(i, i + BATCH));
  const todo = batches.map((b, i) => i).filter((i) => !done.includes(i));
  const bal = ethers.formatEther(await provider.getBalance(addr));

  console.log(`attester  ${addr}  balance ${bal} ETH`);
  console.log(`rows ${rows.length}  batches ${batches.length}  already done ${done.length}  to send ${todo.length}  schema v${SCHEMA}`);
  const dist = {};
  rows.forEach((r) => { dist[r.score] = (dist[r.score] || 0) + 1; });
  console.log("score distribution:", JSON.stringify(dist));
  console.log("sample:", rows.slice(0, 3).map((r) => `${r.address} -> ${r.score}/100 flags=${r.flags}`).join(" | "));

  if (!send) { console.log("DRY RUN — nothing written. Re-run with --send to write."); return; }

  for (const i of todo) {
    const b = batches[i];
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const tx = await registry.attestBatch(
          b.map((r) => r.address), b.map((r) => r.score), b.map((r) => r.flags),
          b.map((r) => ethers.keccak256(ethers.toUtf8Bytes(r.report))), SCHEMA);
        console.log(`batch ${i + 1}/${batches.length} sent ${tx.hash}`);
        const rc = await tx.wait();
        if (rc.status !== 1) throw new Error("reverted");
        done.push(i); fs.writeFileSync(PROGRESS, JSON.stringify(done));
        console.log(`  confirmed https://sepolia-explorer.giwa.io/tx/${tx.hash}`);
        break;
      } catch (e) {
        console.log(`  batch ${i + 1} attempt ${attempt} failed: ${e.shortMessage || e.message}`);
        try { wallet.reset(); } catch (_) {}
        if (attempt === 3) { console.log("stopping — re-run the same command to resume"); process.exit(1); }
        await sleep(4000 * attempt);
      }
    }
    await sleep(1500);
  }
  console.log(`done. totalAttestations = ${await registry.totalAttestations()}`);
})().catch((e) => { console.error(e.shortMessage || e.message); process.exit(1); });
