#!/usr/bin/env node
/**
 * learn-templates.js — teach clone-scout which templates have a verdict.
 *
 *   node learn-templates.js --from-registry [--pages 40]
 *       Walk the registry's Attested events (newest first, 50 per page) written by the watcher's
 *       attester and record each target's template -> {score, flags, reportHash}. Newest verdict wins.
 *
 *   node learn-templates.js --review <file.md> --address 0x.. --score 19 --flags 2
 *       Record a hand review for the template of <address>. A review overrides automated verdicts.
 *
 * Writes templates.json next to this file. Read-only on-chain.
 */
require("dotenv").config();
const fs = require("fs");
const { ethers } = require("ethers");
const { templateKey, TemplateStore } = require("./templates");

const RPC = process.env.GIWA_RPC || "https://sepolia-rpc.giwa.io";
const EXPLORER = process.env.GIWA_EXPLORER || "https://sepolia-explorer.giwa.io";
const REGISTRY = process.env.SCAN_REGISTRY || "0x6C831F9d7051E94589807D2C3d924bb195b5de94";
const WATCHER_ATTESTER = (process.env.WATCHER_ATTESTER || "0xDc62E6e98B61772288F33b0C14178BEE424e76b3").toLowerCase();
const arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : undefined; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const provider = new ethers.JsonRpcProvider(RPC);
  const chainId = (await provider.getNetwork()).chainId;   // recorded in every source label
  const store = new TemplateStore(__dirname + "/templates.json");
  const before = store.size();

  if (process.argv.includes("--review")) {
    const file = arg("--review"), address = arg("--address");
    const score = Number(arg("--score")), flags = Number(arg("--flags"));
    if (!file || !fs.existsSync(file) || !ethers.isAddress(address || "") || !(score >= 0 && score <= 100) || !(flags >= 0 && flags <= 63)) {
      console.error("usage: --review <file.md> --address 0x.. --score 0-100 --flags 0-63"); process.exit(1);
    }
    const t = await templateKey(provider, address);
    if (!t) { console.error("no code at that address"); process.exit(1); }
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes(fs.readFileSync(file, "utf8")));
    store.learn(t.key, { score, flags, reportHash, source: `review:${chainId}:${file.split("/").pop()}`, name: address });
    console.log(`learned review for template ${t.key} -> ${score}/100 flags=${flags}`);
    return;
  }

  if (!process.argv.includes("--from-registry")) { console.error("pass --from-registry or --review (see header)"); process.exit(1); }
  const pages = Number(arg("--pages") || 40);
  let params = null, seen = new Set(), learned = 0;
  for (let p = 0; p < pages; p++) {
    const qs = params ? "?" + new URLSearchParams(params) : "";
    const r = await fetch(`${EXPLORER}/api/v2/addresses/${REGISTRY}/logs${qs}`, { headers: { "User-Agent": "curl/8.5.0" } });
    if (!r.ok) { console.error(`explorer ${r.status}`); break; }
    const d = await r.json();
    for (const it of d.items || []) {
      if ((it.topics || []).length < 3) continue;
      const target = ethers.getAddress("0x" + it.topics[1].slice(-40));
      const attester = ("0x" + it.topics[2].slice(-40)).toLowerCase();
      if (attester !== WATCHER_ATTESTER || seen.has(target)) continue;
      seen.add(target);
      const w = it.data.slice(2).match(/.{64}/g) || [];
      const score = parseInt(w[0], 16), flags = parseInt(w[1], 16), reportHash = "0x" + w[2];
      let t;
      try { t = await templateKey(provider, target); } catch (_) { continue; }
      if (!t || store.get(t.key)) continue;
      store.learn(t.key, { score, flags, reportHash, source: `scan:${chainId}:${target}`, name: target });
      learned++;
    }
    params = d.next_page_params;
    if (!params) break;
    await sleep(150);
  }
  console.log(`checked ${seen.size} attested contracts, learned ${learned} templates (store: ${before} -> ${store.size()})`);
})().catch((e) => { console.error(e.message); process.exit(1); });
