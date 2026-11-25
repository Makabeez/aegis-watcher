# Aegis watcher

Continuously scans **newly verified contracts on GIWA** and writes AI risk
attestations to `ScanRegistry`. This is what turns `totalAttestations` from a
number you increment by hand into a KPI that grows on its own.

- Analysis is delegated to the live `/api/analyze` endpoint → one engine, and
  **no Anthropic key on this box**.
- Dedupe by bytecode: identical code reuses its verdict (`bytecode-cache.json`, see v1.2), and every address is still attested on-chain.
- Writes are batched via `attestBatch()` → ~1 tx per 10 contracts.

---

## Blast radius (read before running)

The watcher needs a key that can sign `attest` transactions. Use a **dedicated
throwaway wallet**, never your main one.

- **Worst single transaction:** writes an attestation (a score + flags + hash)
  for some address, and spends that wallet's testnet gas.
- **Cannot** move ETH or tokens out of any other wallet. The registry is not
  payable and makes no external calls.
- **If the key leaks:** an attacker can spam junk attestations and drain that
  wallet's testnet gas. Nothing else. You revoke instantly with
  `setAttester(<leaked address>, false)` from the owner wallet.

That is the whole exposure — but it's why the attester is a separate key.

---

## Setup

### 1. Create a dedicated attester wallet
```bash
node -e "const w=require('ethers').Wallet.createRandom();console.log('address:',w.address);console.log('key    :',w.privateKey)"
```
Save the key straight into `.env`. Don't paste it into chat, a repo, or an issue.

### 2. Fund it
Send ~**0.01 GIWA-Sepolia ETH** from your main wallet to the new address.
At ~0.001 gwei that covers many thousands of attestations.

### 3. Authorize it (from the OWNER wallet)
Explorer → `ScanRegistry` → **Write Contract** → `setAttester`:
- `attester` = the new address
- `enabled`  = `true`

https://sepolia-explorer.giwa.io/address/0x6C831F9d7051E94589807D2C3d924bb195b5de94

The watcher refuses to start if this step is missing.

### 4. Install
```bash
cd ~/aegis-watcher
npm install
cp .env.example .env      # paste ATTESTER_KEY
```

### 5. Verify before going live
```bash
npm run dry     # one cycle, scans + logs, writes NOTHING on-chain
npm run once    # one real cycle, then exits
```

### 6. Run under PM2
Edit `ecosystem.config.js` and replace `/home/YOURUSER/` with your real path
(**absolute paths only** — relative paths are how phantom PM2 processes happen).
```bash
pm2 start ~/aegis-watcher/ecosystem.config.js
pm2 save --force
pm2 logs aegis-watcher
```
If you ever see PM2 running stale code:
```bash
pm2 delete aegis-watcher && rm -f ~/.pm2/dump.pm2 && pm2 save --force
pm2 start ~/aegis-watcher/ecosystem.config.js
```

---

## Tuning (`.env`)

| Var | Default | Notes |
|---|---|---|
| `INTERVAL_MS` | `3600000` | 1h between cycles |
| `PAGES_PER_RUN` | `2` | 50 contracts per page, newest first |
| `MAX_PER_RUN` | `25` | cap attestations per cycle |
| `BATCH_SIZE` | `10` | contracts per `attestBatch` tx |
| `MIN_BALANCE_ETH` | `0.005` | pauses and warns below this |

Each scan is one Claude call on the contract source — fractions of a cent.
25/hour is comfortably inside a $5 balance for months, but watch the Console
balance for the first few days and set a budget alert.

---

## What good looks like

```
cycle start
fetched 100 verified contracts
12 not yet attested
  scanned 0x750987… HelloGIWA -> 8/100 flags=0 [ai+static]
  attestBatch(10) sent 0x…
  confirmed https://sepolia-explorer.giwa.io/tx/0x…
cycle done — totalAttestations = 20
```

`engine` should read `ai+static` for verified contracts. If it says `static`
with an `aiError`, the Vercel side lost its Anthropic key or ran out of credit —
the watcher keeps working, it just stops adding logic-level findings.

---

## v1.1 additions

**AI-degradation alarm.** If a *verified* contract comes back as anything other
than `ai+static`, the cycle logs `!! AI LAYER DEGRADED` and ends with
`(DEGRADED)`. That is your signal the Anthropic key died or the balance ran out —
without it, the watcher would silently keep attesting bytecode-only scores and
quietly hollow out the product. Grep for it:

```bash
pm2 logs aegis-watcher --lines 200 | grep -i degraded
```

**KPI series.** Every cycle appends to `kpi.csv`:

```
timestamp,totalAttestations,scannedThisCycle,degradedThisCycle
```

That file is your growth chart for the December Finalist review. **Back it up off
this machine** — it cannot be reconstructed later.

## v1.2 — bytecode dedupe

Identical bytecode gets an identical verdict. Before calling the AI, the watcher
hashes the deployed code and reuses any previous verdict for that hash
(`bytecode-cache.json`).

Why it matters: GIWA Sepolia has tens of thousands of verified contracts, most of them
byte-identical template deploys (`HelloGIWA`, `StandardERC20`, `StandardNFT`).
Auditing each one separately costs ~$0.0056 a scan for the same answer. Dedupe
cuts spend by roughly 90% and makes duplicates deterministic — which also removes
the "same contract, different score" inconsistency for templates.

Cached rows log as `[bytecode-match]` and are still attested on-chain per address,
so coverage keeps growing.

## v1.3 — coverage denominator

Once a day the watcher pages the explorer to count total verified contracts and
logs `coverage: N/M verified contracts (X%)`. `kpi.csv` gains a fifth column:

```
timestamp,totalAttestations,scannedThisCycle,degraded,verifiedTotal
```

`verifiedTotal` is blank on cycles that skip the count. Coverage % is the number
worth quoting — it implies completeness, where a raw count only implies activity.

## v1.4 — honest coverage + nonce safety

**Coverage counting.** The old count silently capped at 3,000 and reported it as
fact — GIWA Sepolia actually has 20,000+ verified contracts, so real coverage was
being overstated by ~7x. It now pages until exhausted and returns a completeness
flag. Incomplete counts are recorded as `>=N` and logged as an upper bound, never
as a clean percentage. It runs **weekly**, not daily — the count is ~400 requests.

Never quote a coverage % from a `>=` row. Quote the absolute attestation count.

**Nonce handling.** Writes go through ethers' `NonceManager` (local nonce tracking), the nonce is reset after a failed batch, and
a failed batch waits 6s so an in-flight tx can settle. This fixes the
`nonce has already been used` / `replacement fee too low` errors that were losing
~1 batch (20 contracts) per cycle.

## v1.5 — schema v4, accuracy audit, on-demand scoring (Nov 2026)

- **Schema v4.** Scores are written with `schemaVersion 4`. The bytecode check now stops before the
  Solidity CBOR metadata trailer, whose IPFS hash was being read as fake `DELEGATECALL` / `SELFDESTRUCT`
  opcodes. 1,782 historical scores were corrected on-chain with `rescore.js` (a correction may only lower
  a score). Full write-up: the Accuracy section of the
  [aegis-giwa README](https://github.com/Makabeez/aegis-giwa#accuracy--what-we-found-and-fixed).
- **`attest-one.js`** scores specific addresses on demand, for contracts verified before the watcher's
  window. Dry run by default; `--send` writes one `attestBatch`. It refuses to write a degraded scan.
- **RPC note.** Use an RPC that answers `eth_maxPriorityFeePerGas`. Through a provider that didn't,
  ethers fell back to a 1 gwei priority fee (about 1,000× GIWA's normal 0.001 gwei) and drained the
  attester within hours; the `MIN_BALANCE_ETH` guard then paused writes until it was topped up.
- **Stale watch.** `stale-watch.sh` restarts the watcher and sends an alert if `kpi.csv` stops growing
  for 6 hours.
