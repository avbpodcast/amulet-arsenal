# Amulet Broadcaster

A single-file, self-hosted Bitcoin transaction broadcaster.

Paste a signed PSBT or raw transaction, watch the verification panel, walk a four-step gated confirmation flow, then push the transaction to the network through one of the public block explorers you trust. The page keeps polling for the first confirmation so you can leave the tab open and watch the badge flip from "confirming" to "confirmed".

The third tool in the AVBforge spend pipeline:

```
Amulet Broadcaster           push signed tx to network (this tool)
```

Mainnet only. Open standards (BIP-174 PSBT, Esplora API). No third-party trust beyond the broadcast endpoints you choose.

---

## Quick start

1. Download `amulet_broadcast_v1.01.html`
2. Open it in your browser. That is it.

The whole tool is one HTML file with the crypto bundle inlined. No npm install, no server, no other files needed at run time. Save it to a USB stick, host it on your own domain, or just open it from your downloads folder.

For Tor users: open it in Tor Browser to use the `.onion` endpoints.

---

## What it does

You give it one of two inputs:

- A **signed PSBT** (base64), produced by the Amulet Signer or any wallet that exports BIP-174 PSBTs (Sparrow, Electrum, hardware wallets)
- A **raw transaction hex**, produced by any wallet that lets you export a finalized transaction

The tool auto-detects which one and decodes it locally. You see a verification panel listing every input and output (with addresses and amounts), the fee, and the size in bytes.

Then it walks you through four explicit steps:

1. **Acknowledge** the transaction details are correct (a checkbox you have to tick)
2. **Authorize going online** to probe the broadcast nodes (this step never broadcasts; it only checks which nodes are reachable)
3. **Pick a node** from the list of green "ready" entries (click any of them to switch the selection)
4. **Final confirmation** in a blocking modal that says, in red, "Confirming below can not be undone!"

Only the "Yes, send it" click in step 4 actually fires the broadcast.

After broadcast, the row stays in your session history with a confirmation badge that polls the chosen explorer every 20 seconds. The badge text starts at "confirming", flips to "confirmed" when the transaction has at least one confirmation. Hover the badge to see the block height.

---

## Why this tool exists

Most Bitcoin self-custody users handle generation, storage, and watching their balance in tools they trust (paper backups, hardware wallets, the rest of the Amulet arsenal). The moment they want to actually move funds, the workflow tends to leave that trust boundary and route through whatever a hot wallet decides to broadcast through.

This tool puts the broadcast step under the same care as the rest:

- You see the transaction before it goes anywhere
- You pick the explorer
- You can pick a Tor onion endpoint instead of a clearnet one
- You can run it offline up to the broadcast moment
- You can close the page after it sends (it has done its job; the network has the tx)
- Or you can keep it open and watch the confirmation arrive

---

## Features

### Endpoint coverage out of the box

Eleven clearnet endpoints, two Tor (.onion) endpoints, all editable in the gear settings:

| Endpoint | Type | Notes |
|---|---|---|
| Mempool.space | esplora | canonical |
| Blockchain.com | form | the legacy `pushtx` API |
| Blockstream.info | esplora | canonical |
| Bitaps | json | |
| BTC.network | manual | opens web form, copies hex |
| BestChange | manual | opens web form, copies hex |
| BTCScan | esplora | |
| Blockexplorer.one | manual | opens web form, copies hex |
| Coinb.in | manual | opens web form, copies hex |
| BlockCypher | json | rate-limited free tier |
| Tatum | json | requires API key (disabled by default) |
| Blockstream.info (Tor) | esplora | onion mirror |
| Mempool.space (Tor, official) | esplora | onion mirror |

You can add your own via the gear: any Esplora-compatible node, any JSON or form-POST endpoint, or your own manual web form. The four adapter types cover everything Bitcoin explorers actually expose.

### Tor support

A pill toggle in the topbar switches between clearnet and Tor mode. When Tor is on, only `.onion` endpoints are used. **Strict isolation:** a Tor broadcast never auto-falls-back to a clearnet endpoint, and vice versa. Tor mode only resolves `.onion` addresses if the page is loaded in Tor Browser (or a regular browser configured to route requests through a Tor proxy).

### Confirmation tracking with fallback

After a successful broadcast, the row's "confirming" badge polls the chosen explorer every 20 seconds. If that explorer fails (rate limit, 403, transient error), the poll automatically falls back to other reachable endpoints in the same network. The badge only turns red ("check failed") if every fallback fails. Hover any badge to see what happened.

### Already-broadcast recovery

Pasting an old, already-broadcast transaction does not produce a useless error. The tool detects the "duplicate / already exists / already in chain" responses across all the supported endpoint types, marks the row as success, and starts the same confirmation polling as for a fresh broadcast.

### Settings panel

Gear icon top-right opens a modal where every endpoint in the list is editable. Click an entry to expand and see every field: name, type, full URL, body field name (for json/form types), JSON path to extract the txid from the response, tx-explorer URL pattern (with `{txid}` placeholder), health-check URL, optional API key + key-header. Add a custom slot for your own private node. Restore defaults to wipe back to the seed list.

Settings persist in `localStorage`. They survive reload but never leave your browser.

### Theme switch

A small `◐ theme` button in the topbar toggles between dark and light. Both share all layouts; only the colour tokens swap. Persists per browser.

---

## Security model

### What this tool does NOT do

- **Hold or sign with private keys.** The Broadcaster only ever sees signed transactions. If you accidentally paste a seed phrase, the tool refuses to decode it and tells you the right tool to use instead.
- **Phone home.** No telemetry, no analytics, no remote logging. The only outbound HTTP requests are the broadcast itself and the optional 20-second confirmation polls, both to user-controlled explorer URLs.
- **Persist anything to a server.** Endpoint settings, theme choice, and the chosen network live in your browser's `localStorage`. The session broadcast history is in-memory only and disappears when you close the tab.

### What this tool DOES do

- Inlines a pinned, **reproducibly-built crypto bundle** (`@scure/btc-signer`, `@scure/bip32`, `@scure/bip39`, `@noble/hashes`, `@noble/curves`, `@scure/base`). The bundle SHA-256 is in source so any auditor can verify the bytes match upstream npm releases.
- Refuses BIP-39 seed phrases as input on the load card.
- Shows a **verification panel** before any irreversible action: input addresses, output addresses, amounts, fees.
- Requires **three explicit user actions** between paste and broadcast: acknowledge checkbox, online-go button, final-confirm Yes.
- Strictly isolates Tor and clearnet network paths.

### What is on you

- Audit the verification panel before clicking "Yes, send it". A maliciously crafted PSBT that parses but spends to addresses you did not intend is something only you can catch by reading the panel.
- Pick endpoints you trust. Public broadcast services see the IP that pushed the transaction. If that matters, use Tor mode and a Tor browser.
- Verify the file SHA-256 matches the published release before opening it (see `SHA256.txt`).

---

## Reproducible build

The crypto bundle is built from upstream npm packages with `esbuild`. The recipe:

```bash
npm i @scure/bip32@1.7.0 \
      @scure/base@1.2.1 \
      @noble/hashes@1.6.1 \
      @noble/curves@1.9.0 \
      @scure/btc-signer@1.5.0 \
      @scure/bip39@1.5.0 \
      esbuild

cat > entry.js <<'EOF'
export { HDKey } from '@scure/bip32';
export { base58check, bech32 } from '@scure/base';
export { sha256 } from '@noble/hashes/sha256';
export { ripemd160 } from '@noble/hashes/ripemd160';
export * as btc from '@scure/btc-signer';
export { secp256k1 } from '@noble/curves/secp256k1';
export * as bip39 from '@scure/bip39';
export { wordlist as wordlistEnglish } from '@scure/bip39/wordlists/english';
EOF

esbuild entry.js \
  --bundle --format=iife --global-name=AmuletTx \
  --target=es2020 --minify \
  --outfile=amulet-tx-bundle.js

sha256sum amulet-tx-bundle.js
# 1e4f107f3822f9e0d439829e665b703812a64542068abecac13579acf6b594c3
```

The standalone `amulet-tx-bundle.js` next to the HTML in this repo is byte-identical to the bytes inlined into `amulet_broadcast_v1.01.html`. You can verify by extracting the inlined `<script>` block and hashing.

---

## File layout

```
amulet_broadcast_v1.01.html   the tool: open this in a browser
amulet-tx-bundle.js               reference copy of the inlined bundle
SHA256.txt                        hashes of the above
PLAN.txt                          architecture + history notes
README.md                         this file
_archive/                         v0.01..v0.16 prototypes (development history)
```

On the published site only the tool, `SHA256.txt` and this README ship; the
reference bundle copy, `PLAN.txt` and `_archive/` live in the source
repository.

---

## Browser support

Tested in current Firefox and Chromium-based browsers. Uses standard fetch, vanilla DOM APIs, no service workers, no localStorage gymnastics. Should work in any modern browser that supports ES2020.

For Tor onion endpoints, you must use Tor Browser (or a regular browser configured to route to a Tor SOCKS proxy). A normal Chrome or Firefox cannot resolve `.onion` addresses at the network layer.

---

## What this tool does NOT replace

- **A wallet.** It does not generate keys, store keys, sign transactions, or display your balance.
- **A full node.** It uses public block explorers as broadcast endpoints. If you run your own Bitcoin Core node with the Esplora server on top, you can add it as a custom endpoint in the settings.
- **Cold-storage discipline.** This tool runs in a regular browser. Treat it like any browser-based Bitcoin tool: verify before clicking, and use Tor mode if the broadcast IP matters to you.

---

## Roadmap

Out of scope for v1.01, may land in future releases:

- QR-based PSBT transfer (camera capture + display) for true air-gap workflows
- Multi-signature coordination beyond fully-signed PSBTs
- Replace-by-fee (RBF) and fee-bump workflows
- Direct-to-node broadcast over a user-supplied Bitcoin Core RPC URL
- Automated signed-PSBT validity checks (spend-policy linting before broadcast)

---

## Acknowledgments

Built on the excellent crypto libraries by Paul Miller (`@scure`, `@noble`). PSBT parsing, signing primitives, address codecs, and BIP-39 mnemonic handling all come from those libraries; this tool is the broadcast and confirmation orchestration layer around them.

Esplora API ([blockstream/electrs](https://github.com/Blockstream/electrs)) is the de facto standard for Bitcoin block explorers and powers the majority of the supported endpoints.

---

## License

Free and open source. See the `LICENSE` file in this repository.

---

## Project home

Part of the [AVBforge](https://avbforge.com) Amulet Arsenal. The full set:

- **Amulet Generator**: offline wallet generator with verifiable entropy
- **Amulet Vault**: encrypted local store for seeds, descriptors, PSBTs
- **Amulet Scryer**: watch-only balance checker
- **Silent Amulet**: BIP-352 silent payments wallet
- **Amulet Timelock**: time-locked redeem-script generator
- **Amulet Transaction Creator**: offline PSBT builder
- **Amulet Signer**: offline PSBT signer
- **Amulet Broadcaster** *(this tool)*: signed-tx broadcaster + confirmation tracker
                                                                                                                                  