// /api/analyze — Aegis analysis pipeline (Vercel Node serverless, zero deps)
// GET  /api/analyze?address=0x...   or   POST {address}
// Pipeline: eth_getCode -> bytecode heuristics -> Blockscout verified source -> Claude audit -> merged result

const RPC = "https://sepolia-rpc.giwa.io";
const EXPLORER_API = "https://sepolia-explorer.giwa.io/api/v2";
const MODEL = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-6";
const MAX_SOURCE_CHARS = 60000;       // cap what we send to the model
const MAX_TOKENS = 1500;
const CACHE_TTL_MS = 10 * 60 * 1000;  // per warm instance
const RL_PER_MIN   = parseInt(process.env.RL_PER_MIN   || "8", 10);    // per IP
const RL_DAILY_MAX = parseInt(process.env.RL_DAILY_MAX || "500", 10);  // AI calls/day/instance

const CAT_TO_FLAG = {
  "reentrancy": 1, "access-control": 2, "dangerous-approval": 4,
  "honeypot-rug": 8, "oracle-manipulation": 16, "unsafe-upgrade": 32,
};
// Deterministic scoring: the model reports FINDINGS, code computes the SCORE.
// Same findings => same score, every time. No free-form number from the LLM.
const SEV_WEIGHT = { low: 2, medium: 8, high: 20, critical: 45 };
const BASE_SCORE = 6;
// Dominant finding sets the tone; additional findings add at a discount, so a
// contract with many minor notes never outranks one with a real vulnerability.
function scoreFromFindings(findings) {
  const w = findings.map((f) => SEV_WEIGHT[f.severity] || 0).sort((a, b) => b - a);
  if (!w.length) return BASE_SCORE;
  const rest = w.slice(1).reduce((a, b) => a + b, 0);
  return Math.max(0, Math.min(100, Math.round(BASE_SCORE + w[0] + 0.35 * rest)));
}

const FLAG_NAMES = [
  [1, "Reentrancy"], [2, "Access control"], [4, "Dangerous approval"],
  [8, "Honeypot / rug"], [16, "Oracle manipulation"], [32, "Unsafe upgrade"],
];

const UA = { "User-Agent": "Mozilla/5.0 (Aegis/1.0)", "Accept": "application/json" };
const cache = new Map();
const hits = new Map();          // ip -> [timestamps]
let day = new Date().toISOString().slice(0, 10);
let dayCount = 0;                // AI calls today (per warm instance)

function clientIp(req) {
  const h = req.headers || {};
  return String(h["x-forwarded-for"] || h["x-real-ip"] || "unknown").split(",")[0].trim();
}
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();          // crude memory bound
  return arr.length > RL_PER_MIN;
}
function budgetLeft() {
  const today = new Date().toISOString().slice(0, 10);
  if (today !== day) { day = today; dayCount = 0; }
  return dayCount < RL_DAILY_MAX;
}

async function rpc(method, params) {
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json", ...UA },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!r.ok) throw new Error(`rpc ${r.status}`);
  const j = await r.json();
  if (j.error) throw new Error(`rpc: ${j.error.message || "error"}`);
  return j.result;
}

// ---- static bytecode heuristics (opcode walk, skips PUSH immediates) ----
function heuristics(codeHex) {
  const code = codeHex.startsWith("0x") ? codeHex.slice(2) : codeHex;
  const bytes = [];
  for (let i = 0; i < code.length; i += 2) bytes.push(parseInt(code.substr(i, 2), 16));
  const ops = new Set(), push4 = new Set();
  for (let i = 0; i < bytes.length; i++) {
    const op = bytes[i]; ops.add(op);
    if (op >= 0x60 && op <= 0x7f) {
      if (op === 0x63) { const s = code.substr((i + 1) * 2, 8).toLowerCase(); if (s.length === 8) push4.add(s); }
      i += op - 0x5f;
    }
  }
  const findings = []; let flags = 0, score = 8;
  const add = (bit, sev, title, expl, pts) => { flags |= bit; score += pts; findings.push({ category: keyOf(bit), severity: sev, title, explanation: expl, source: "bytecode" }); };
  if (ops.has(0xf4)) add(32, "high", "Uses DELEGATECALL", "Proxy / upgradeable pattern: the contract's logic can be swapped by whoever controls the implementation.", 26);
  if (ops.has(0xff)) add(8, "high", "Contains SELFDESTRUCT", "The contract can be destroyed and its balance redirected.", 24);
  if (push4.has("3659cfe6") || push4.has("4f1ef286")) add(32, "medium", "Exposes upgradeTo", "UUPS-style upgrade entrypoint is present.", 12);
  if (push4.has("095ea7b3") || push4.has("a22cb465")) add(4, "low", "Exposes approval interface", "approve / setApprovalForAll present — check allowance scope before signing.", 8);
  if (ops.has(0xf1) || ops.has(0xfa)) { score += 6; findings.push({ category: "other", severity: "low", title: "Makes external calls", explanation: "Interacts with other contracts.", source: "bytecode" }); }
  if (bytes.length < 80) { score += 6; findings.push({ category: "other", severity: "low", title: "Very small bytecode", explanation: "Minimal / opaque contract.", source: "bytecode" }); }
  return { flags, score: Math.max(0, Math.min(100, Math.round(score))), findings, size: bytes.length };
}
function keyOf(bit) { for (const k in CAT_TO_FLAG) if (CAT_TO_FLAG[k] === bit) return k; return "other"; }

// ---- verified source from Blockscout ----
async function fetchContract(addr) {
  const r = await fetch(`${EXPLORER_API}/smart-contracts/${addr}`, { headers: UA });
  if (r.status === 404) return { verified: false };
  if (!r.ok) return { verified: false, error: `explorer ${r.status}` };
  const d = await r.json();
  return {
    verified: !!d.is_verified,
    name: d.name || null,
    compiler: d.compiler_version || null,
    source: d.source_code || null,
  };
}

// ---- Claude source audit ----
const SYSTEM = `You are a senior smart-contract security auditor. Analyze the provided Solidity source for risks to users who interact with it.
Respond with ONLY a JSON object — no prose, no markdown fences — with exactly this shape:
{"summary": "<1-2 plain-English sentences a non-technical user understands>",
 "findings": [{"category": "<reentrancy|access-control|dangerous-approval|honeypot-rug|oracle-manipulation|unsafe-upgrade|other>",
               "severity": "<low|medium|high|critical>",
               "title": "<short title naming the function or pattern>",
               "explanation": "<1-2 sentences, plain English, why it matters to a user>"}]}
Do NOT output a numeric score — severity per finding is what matters, and the score is computed from it.\nRules: report only real, evidenced issues present in the code and name the function/pattern. Do not invent issues. If the contract is clean, return an empty findings array and a low score. Be calibrated: standard safe patterns (OpenZeppelin Ownable/ERC20/ERC721) are not findings by themselves. Owner-only mint, blacklist, fee changes, or pause that can harm holders IS honeypot-rug risk. Approvals to arbitrary or unbounded addresses are dangerous-approval. Proxy/delegatecall/upgradeable logic is unsafe-upgrade unless clearly access-controlled and timelocked. Missing or weak permission checks on state-changing functions are access-control.`;

async function aiAudit(name, source) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error("AI disabled: ANTHROPIC_API_KEY not set");
  let truncated = false;
  if (source.length > MAX_SOURCE_CHARS) { source = source.slice(0, MAX_SOURCE_CHARS); truncated = true; }
  const user = `Contract name: ${name || "unknown"}${truncated ? " (source truncated)" : ""}\n\n\`\`\`solidity\n${source}\n\`\`\``;
  const headers = { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" };
  const ws = process.env.ANTHROPIC_WORKSPACE_ID;
  if (ws) headers["anthropic-workspace-id"] = ws;
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify({ model: MODEL, max_tokens: MAX_TOKENS, temperature: 0, system: SYSTEM, messages: [{ role: "user", content: user }] }),
  });
  if (!r.ok) { const t = await r.text(); throw new Error(`anthropic ${r.status}: ${t.slice(0, 160)}`); }
  const d = await r.json();
  const text = (d.content || []).map(c => c.text || "").join("").trim();
  const clean = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  let parsed;
  try { parsed = JSON.parse(clean); } catch { throw new Error("AI returned non-JSON"); }
  const findings = (Array.isArray(parsed.findings) ? parsed.findings : []).map(f => ({
    category: CAT_TO_FLAG[f.category] ? f.category : "other",
    severity: ["low", "medium", "high", "critical"].includes(f.severity) ? f.severity : "medium",
    title: String(f.title || "Finding").slice(0, 120),
    explanation: String(f.explanation || "").slice(0, 400),
    source: "ai",
  }));
  let flags = 0; for (const f of findings) flags |= (CAT_TO_FLAG[f.category] || 0);
  const score = scoreFromFindings(findings);
  return { score, flags, findings, summary: String(parsed.summary || "").slice(0, 400), truncated, model: MODEL, usage: d.usage || null };
}

module.exports = async (req, res) => {
  res.setHeader("content-type", "application/json");
  res.setHeader("cache-control", "no-store");
  try {
    const address = String((req.method === "POST" ? (req.body && req.body.address) : (req.query && req.query.address)) || "").trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return res.status(400).end(JSON.stringify({ ok: false, error: "invalid address" }));
    const internal = process.env.AEGIS_INTERNAL_KEY &&
      (req.headers || {})["x-aegis-key"] === process.env.AEGIS_INTERNAL_KEY;
    const ip = clientIp(req);
    if (!internal && rateLimited(ip)) {
      res.setHeader("retry-after", "60");
      return res.status(429).end(JSON.stringify({ ok: false, error: "Rate limit: max " + RL_PER_MIN + " scans/min. Try again shortly." }));
    }

    const key = address.toLowerCase();
    const hit = cache.get(key);
    if (hit && Date.now() - hit.t < CACHE_TTL_MS) return res.status(200).end(JSON.stringify({ ...hit.result, cached: true }));

    const code = await rpc("eth_getCode", [address, "latest"]);
    if (!code || code === "0x") return res.status(200).end(JSON.stringify({ ok: false, error: "No contract code at this address (EOA / wallet)." }));

    const h = heuristics(code);
    const c = await fetchContract(address);

    let ai = null, aiError = null;
    if (c.verified && c.source) {
      if (!budgetLeft()) {
        aiError = "Daily AI budget reached — bytecode analysis only.";
      } else {
        try { dayCount++; ai = await aiAudit(c.name, c.source); } catch (e) { aiError = e.message; }
      }
    } else if (!c.verified) {
      aiError = "Contract not verified — bytecode analysis only.";
    }

    const flags = h.flags | (ai ? ai.flags : 0);
    const allFindings = [...(ai ? ai.findings : []), ...h.findings];
    const score = ai ? scoreFromFindings(allFindings) : h.score;  // deterministic: f(findings)
    const findings = allFindings;
    const summary = ai ? ai.summary
      : (findings.length ? `Bytecode analysis found ${findings.length} signal(s). ${c.verified ? "" : "Source is unverified, so logic-level risks could not be assessed."}`.trim()
                         : "No high-risk patterns detected in bytecode.");
    const report = JSON.stringify({ address: key, score, flags, engine: ai ? "ai+static" : "static", model: ai ? ai.model : null, summary, findings: findings.map(f => f.title) });

    const result = {
      ok: true, address, name: c.name || null, verified: !!c.verified, compiler: c.compiler || null,
      engine: ai ? "ai+static" : "static", model: ai ? ai.model : null,
      score, flags, flagList: FLAG_NAMES.filter(([b]) => flags & b).map(([, n]) => n),
      findings, summary, truncated: ai ? ai.truncated : false, aiError, report, bytecodeSize: h.size,
      scoring: { base: BASE_SCORE, weights: SEV_WEIGHT, note: "score = base + top severity + 0.35 x remaining severities, capped 0-100" },
    };
    cache.set(key, { t: Date.now(), result });
    return res.status(200).end(JSON.stringify(result));
  } catch (e) {
    return res.status(500).end(JSON.stringify({ ok: false, error: e.message || "analysis failed" }));
  }
};