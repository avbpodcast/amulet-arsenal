# Amulet Vault — format & usage

A single `amulet_vault.html` file plus `.enc` wallet files in the same folder.
Everything is encrypted except the HTML itself (which holds no secrets).

## How to use

1. Save `amulet_vault.html` anywhere on disk.
2. **Go offline** (unplug / airplane mode) before touching real funds.
3. Open the file in your browser.

### First use
- Click **Create new vault** → choose a master password → pick a folder to store the vault in (Chromium browsers: direct
  folder sync; others: in-memory, use *Backup .zip* to save).
- Click **+ Add wallet** to paste a seed phrase from anywhere and assign a
  wallet password. Each wallet gets its own `.enc` file.

### Later uses
- Click **Open existing vault** → pick the folder, or drop `vault.meta` and your
  `.enc` files on the drop zone.
- Enter master password.
- Click a wallet card → enter that wallet's password to reveal its seed.

### Wallet files in a different folder than vault.meta (v1.51+)
Some users prefer to keep `amulet_vault.html`, `vault.meta`, and the wallet
`.enc` files in different folders for separation of concerns. The vault now
supports this in two ways:

**On-demand pick at wallet-open time (v1.51).** If you click a wallet and its
`.enc` file is not loaded, an inline "Locate file..." picker appears next to
the password input. Click it, choose the `.enc` from wherever it lives, and
the vault adds it to memory and continues with decryption. Use this for one-off
cases where a single wallet's file is somewhere unexpected.

**Two-folder pick at open time (v1.52).** Click **Open existing vault**, then
expand the **⚙ Advanced: wallets in a different folder?** disclosure and tick
the checkbox. When you then click **Open vault folder** the browser asks for
two folders in sequence:

1. The **vault folder** (must contain `vault.meta`).
2. The **wallets folder** (contains the `.enc` files).

Both folders' `.enc` contents merge into memory. After unlock, every wallet
opens directly without per-file prompts. New wallets added in this session
save into the **wallets folder**; `vault.meta` updates save into the **vault
folder**. Deleting a wallet removes the `.enc` from whichever folder it lived
in. Lock / Forget clears both folder handles from memory.

The two-folder mode is session-only: the browser cannot persist folder
handles across reloads safely. Re-pick on each session if you want to keep
the split. Requires a Chromium-based browser (File System Access API).
Single-folder users see no change; the disclosure stays collapsed by default
and the checkbox is off.

### Viewing public addresses
- After unlocking a wallet, click **Show first 3 addresses** inside the view
  modal to derive the first 3 receive addresses for each script type:
  - Legacy · BIP-44 · P2PKH  (`1…`)
  - Nested SegWit · BIP-49 · P2SH-P2WPKH  (`3…`)
  - Native SegWit · BIP-84 · P2WPKH  (`bc1q…`)
  - Taproot · BIP-86 · P2TR  (`bc1p…`)
- Derivation runs entirely locally (~70 ms on modern hardware) using
  noble-secp256k1 + RIPEMD-160 + BIP-32/39 + Bech32. The network sentinel
  counter confirms zero outbound requests during derivation.
- Same algorithm as Amulet v1.3+, so you can cross-verify: paste the seed
  into Amulet and addresses must match byte-for-byte. Using the canonical
  test mnemonic `"abandon abandon abandon abandon abandon abandon abandon
  abandon abandon abandon abandon about"` (no passphrase), the first
  addresses must be:
  ```
  legacy:  1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
  nested:  37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf
  native:  bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
  taproot: bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
  ```
- **The vault does NOT display balances or UTXOs.** That would require
  network requests, and the Network Sentinel blocks those. This is a
  deliberate design choice: the vault manages wallets, not the blockchain.
  Use a dedicated watch-only wallet or a block explorer if you need balance
  information.

### Importing Amulet-generated `.enc` files
- The vault **reads Amulet v1.3+ encrypted reports directly**. Click
  **Import .enc file**, drop/pick the file, enter the password you used in
  Amulet. The full report is decoded, the seed extracted, and the original
  report (addresses, xpubs, entropy details) is preserved verbatim in the
  wallet's notes field.
- Older/vault-native JSON-wrapped `.enc` files are still supported — they
  import as-is with their existing password.

### Exporting a wallet back out
- Open a wallet → **Export…** → choose one of:
  - **Amulet-compatible .enc** (binary `AMLT` format, set a new password) —
    decryptable in Amulet v1.3+'s decrypt tab, suitable for offline emergency
    recovery.
  - **Plaintext .txt report** — the human-readable report. Don't store this on
    synced/cloud folders.

### Lock / auto-lock
- `Ctrl/Cmd + L` to lock.
- Auto-locks after 5 min idle, or immediately when the tab is hidden.

### Verifying file integrity
- On the lock screen, a collapsible **"Don't trust, verify this file"** bar
  expands to a drop zone. Drop your copy of `amulet_vault.html` onto it and
  the browser computes SHA‑256; compare against the canonical hash published
  on the release page. After a successful check, the collapsed bar shows
  `Verified file: <first8>…<last8>` in green.
- Browsers block pages opened from `file://` from reading their own source,
  so the hash can't be auto-computed at load time. The drop-zone sidesteps
  this: the browser reads the file via the standard file-picker API and
  hashes it in-memory. No network, no file write.
- Alternatively compute it yourself on the command line:
  - `sha256sum amulet_vault.html` (Linux / macOS)
  - `shasum -a 256 amulet_vault.html` (macOS BSD)
  - `Get-FileHash amulet_vault.html -Algorithm SHA256` (Windows PowerShell)
- **Honest limitation**: by the time the integrity panel is visible, the page
  has already loaded. A sufficiently tampered HTML could fake any hash it
  wants. For files you don't trust, always verify from the command line
  *before* opening in a browser.

### Verifying the crypto stack
- The **"Verify crypto primitives"** bar runs published test vectors against
  the browser's Web Crypto API and shows pass/fail for each. Runs
  automatically on every page load (~40 ms). Click to expand details.
- Vectors used (all independently reproducible):
  - **PBKDF2-HMAC-SHA256** with `password="password"`, `salt="salt"`, iter=1
    and iter=4096 (widely cited, reproducible with `openssl kdf` or Python's
    `hashlib.pbkdf2_hmac`)
  - **AES-256-GCM** test cases 13 and 14 from McGrew & Viega's original GCM
    specification (all-zero key, all-zero IV; empty plaintext for case 13,
    16-byte zero plaintext for case 14)
  - **SHA-256** of `"abc"` from FIPS 180-4
  - **secp256k1** `getPublicKey(priv=1)` returns the compressed generator
    point (SEC 2 / BIP-340). This covers the EC code used for address
    derivation.
- Each row's "details" expander shows the full input, expected hex, and
  computed hex, so you can re-run the same inputs in `openssl`, Python, or
  anything else and confirm the browser's crypto is producing correct output.
- If any vector fails, the crypto path is broken — don't enter a real seed.

### Network sentinel
- At startup, every outbound network API is monkey-patched: `fetch`,
  `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `EventSource`, dynamically
  set `<img>.src` / `<script>.src` / `<link>.href` / `<iframe>.src`, and
  `serviceWorker.register`.
- Policy: allow same-origin reads (for integrity self-fetch on HTTPS) and
  `data:`/`blob:` URLs (in-memory). Block everything else; log it; throw or
  reject so calling code can't pretend the request went through.
- The **"Network sentinel"** bar shows a live counter: `0 blocked` in green,
  flips to `N blocked` in red if anything tries to call home. Expand to see
  the log of every attempt with URL, kind, and reason.
- The older online-status code used to actively probe `gstatic.com` /
  `cloudflare.com` — those probes have been removed. Online status now uses
  passive `navigator.onLine` + the `online`/`offline` events (browser state,
  not requests). Nothing actually leaves the page, which makes *"nothing
  ever leaves this page"* a fact the sentinel can verify.
- **Honest limitation**: the sentinel lives in the same file it's trying to
  protect, so a sufficiently targeted tampered build could unpatch it before
  running. The sentinel catches the bulk of cases — accidental requests,
  typos, unsophisticated tampering — but for a file you don't trust at all,
  pair it with the command-line SHA-256 check.

### Independent recovery — `amulet_relic.py`
- Every `.enc` and `vault.meta` file is decryptable by
  [`amulet_relic.py`](https://codeberg.org/avbforge/pages) — a
  standalone Python script (~100 lines of actual logic) that uses only
  `cryptography` + stdlib. It reads every format the vault produces:
  vault-native wallet `.enc`, vault-native timelock `.enc`
  (`AMULET_TIMELOCK_V1`), `vault.meta`, and Amulet v1.3+ binary `AMLT`. If
  the vault HTML is ever lost or becomes unrunnable, your data is still
  recoverable.
- Subcommands:
  - `decrypt <file>` — decrypt and print the payload
  - `inspect <file>` — show file type + KDF params without decrypting
  - `list <vault.meta>` — decrypt the index and list every entry with its
    kind (wallet / timelock)
  - `export-txt <timelock.enc>` — re-emit the verbatim `.txt` backup that
    was imported (the timelock payload preserves `originalTxt` byte-for-byte)
  - `verify` — run built-in crypto KAT vectors (SHA-256 FIPS 180-4,
    PBKDF2-SHA-256, AES-256-GCM NIST, end-to-end round-trip at 600k iter)
    so you can prove the crypto stack is functioning before trusting it
    with a real recovery.
- **YubiKey-protected vault.meta is not recoverable here** — the WebAuthn
  hmac-secret output can't be reproduced outside a browser with the key
  attached. Use the vault HTML in that case. Your individual wallet/timelock
  `.enc` files are *not* YubiKey-protected and can always be decrypted
  with this script using their per-item passwords, even without the index.

### Backup
- Click **⇓ Backup .zip** to download the whole vault as a single archive.
- Click **Import from .zip backup** to restore.

## Crypto

- **AES-GCM-256** for every encrypted payload.
- **Argon2id** (memory-hard, GPU/ASIC-resistant) for the master password and
  every wallet/timelock password, as of v1.08. Parameters since v1.63:
  `t=2 iterations, m=262144 KiB (256 MiB), p=1 parallelism, 32-byte output`
  (memory raised from 128 MiB so a stolen file resists GPU/ASIC brute-force
  farms). 16-byte random salt and 12-byte random IV per file.
- **PBKDF2-SHA-256, 600 000 iterations** is preserved only for two specific
  paths where the format isn't ours to change: BIP-39 mnemonic-to-seed (spec
  requirement) and the Amulet v1.3+ binary `.enc` format (cross-tool interop
  with the original Amulet wallet creator).
- **Strict master-password policy**: at least 10 characters and ≥ 70 bits of
  estimated entropy. The estimator rejects common passwords, keyboard runs,
  digit sequences, and short single-word attempts. Passphrase-style input
  (6+ random words) is the recommended way to clear the threshold.
- **YubiKey was removed in v1.06**; v1.06+ refuses to open older meta files
  that carry a `yubikey` field.
- Each wallet file is standalone — decryptable with just its own password, no
  dependency on the vault index.
- No backward compatibility with pre-v1.08 (PBKDF2) vault files — the project
  had no users at the migration point.

## File formats

### `vault.meta` (vault-native, JSON wrapper)

```json
{
  "v": 2,
  "type": "amulet-vault-meta",
  "kdf": { "name":"Argon2id", "m":262144, "t":2, "p":1, "salt":"base64" },
  "iv":  "base64",
  "ct":  "base64"
}
```

Decrypted payload:

```json
{
  "magic": "AMULET_VAULT_V1",
  "createdAt": "ISO8601",
  "wallets": [
    { "id":"w-…", "name":"…", "createdAt":"ISO", "file":"w-….enc" }
  ]
}
```

### `*.enc` wallet file — vault-native (JSON wrapper)

```json
{
  "v": 2,
  "type": "amulet-wallet",
  "kdf": { "name":"Argon2id", "m":262144, "t":2, "p":1, "salt":"base64" },
  "iv":  "base64",
  "ct":  "base64"
}
```

Decrypted payload:

```json
{
  "magic": "AMULET_WALLET_V1",
  "name": "…",
  "createdAt": "ISO",
  "words": ["abandon", "…", "…"],
  "passphrase": "",
  "notes": "",
  "source": "vault-add" | "amulet-enc-import" | "external"
}
```

### `*.enc` wallet file — Amulet v1.3+ native (binary)

Raw byte layout (no JSON):

```
offset  length  content
──────  ──────  ────────────────────────────
   0     4      MAGIC = "AMLT" (0x41 0x4D 0x4C 0x54)
   4     1      VERSION = 0x01
   5    16      PBKDF2 salt (random)
  21    12      AES-GCM IV (random)
  33     *      AES-GCM ciphertext (includes trailing 16-byte auth tag)
```

Plaintext is the full wallet report as UTF-8 text (same content as the `.txt`
download from Amulet). The vault detects this format by its magic bytes and
routes it through a decrypt stage automatically.

## Interop matrix

|                          | Amulet v1.3+ produces  | Vault produces (native)  | Vault produces (exported) |
|--------------------------|------------------------|--------------------------|---------------------------|
| Amulet v1.3+ reads       | ✓                      | ✗                        | ✓                         |
| Vault reads              | ✓                      | ✓                        | ✓                         |

In short: **anything encrypted by Amulet can be read by the vault, and the
vault can produce files that Amulet can read back**. The native vault format
(JSON wrapper) is vault-internal only.

## Notes

- No network. Everything runs in your browser from the local HTML file.
- The HTML file itself is safe to share / back up — it holds no secrets.
- Losing the master password means losing access to the wallet index (names,
  dates), but your `.enc` files are still individually decryptable with their
  wallet passwords.
- Losing a wallet password means losing that wallet. There is no recovery.
- Deleting a wallet overwrites its file with zeros before unlinking (File
  System Access API mode). If you've copied it elsewhere, those copies remain.
