# Amulet · Bitcoin Offline Wallet Generator

**v1.63** — a single HTML file that generates a BIP-39 seed phrase and the
Bitcoin wallets derived from it, entirely inside your browser, with no network
access of any kind.

SHA-256 `69de86d4c8a8d14abbdc5d93f70af6295ee8ceb6268ad6cdc172c9af17a44a92`

---

## Contents

| File | What it is |
|---|---|
| `amulet_1_63.html` | The tool. One self-contained file, no dependencies. |
| `CHECKSUMS.txt` | SHA-256 and BLAKE2b digests, and how to check them. |
| `RELEASE-NOTES.md` | Full changelog and security findings, v1.58 → v1.62. |
| `README.md` | This file. |

---

## Before anything else: verify the file

Everything below is worthless if the file is not the file that was audited.
A modified copy could bias the entropy and look identical.

```
Linux / BSD    sha256sum  amulet_1_63.html
macOS          shasum -a 256  amulet_1_63.html
Windows        certutil -hashfile amulet_1_63.html SHA256
PowerShell     Get-FileHash amulet_1_63.html -Algorithm SHA256
```

Compare against `CHECKSUMS.txt` — but read the warning there first. **A checksum
is only worth as much as the channel it reached you through.** If the file and
the digest came down the same wire from the same server, a compromise of that
server defeats both at once. Get the digest from somewhere the file did not come
from.

The page can also verify itself: open it, expand *"Verify this file before you
trust it"*, and drop the `.html` onto the panel.

---

## Using it

**For real funds, work offline.** The intended workflow:

1. Save the file to disk.
2. Disconnect from Wi-Fi. Unplug the Ethernet cable.
3. Open the saved file from disk.
4. Confirm the pill in the top-right reads **"No network detected"** — treat it
   as one confirmation among several, not proof. You are the one who can see the
   cable.
5. Generate.
6. Write the seed phrase on paper or steel. Never photograph it. Never type it
   into an internet-connected device.
7. Use the **Reset and wipe all data on this browser** button before closing the tab.

The page makes no network requests — verified at runtime with every non-`file://`
request intercepted. There is no `fetch`, no `XMLHttpRequest`, no WebSocket, no
external script, style, font or image. But an air gap protects you from things
this page cannot control, which is the point of working offline.

---

## Choosing entropy

**CSPRNG only is the default, and it is sufficient.** The browser's
`crypto.getRandomValues` supplies 256 bits from the operating system. That is a
cryptographically strong seed on its own, and most people should stop here.

The other sources exist for one scenario: **you do not trust the CSPRNG.** If it
were backdoored or broken, an attacker would know that part of the input and
brute-force the rest — so your wallet's surviving security would be exactly what
your own draws contributed, and nothing more.

That is why no source can be used below **128 bits**:

| Source | Minimum | Bits | Verifiable by you? |
|---|---|---|---|
| **Dice** (D6) | 50 rolls | 129.2 | **Yes** — `50 × log₂(6)`, arithmetic you can check on paper |
| **Dice**, full strength | 99 rolls | 255.9 | Yes |
| **Cards** | 6 rounds of 4 | 135.8 | Mostly — assumes a genuine shuffle, which is partly detected |
| **Chaos grid** | ~30 clicks | 128.0 | No — relies on estimates of your click timing and aim |

The grid deals a fresh board automatically if it runs low on tiles, keeping your
clicks, so it can never leave you stranded below the floor.

**If you want entropy you can fully verify yourself, use dice.**

Sources are mixed in as `SHA-256(csprng ‖ your input)`, so they can only ever
add. Adding nothing is a perfectly valid choice.

### Reproducible mode

Ticking *Reproducible mode* skips the CSPRNG entirely, so your dice or card notes
alone regenerate the wallet later. Your backups already work without this — every
wallet reproduces from its seed phrase, or from the `.txt` / `.pdf` / `.enc`
export.

Because there is no CSPRNG behind it, this mode demands the **full** count: 99
D6 rolls for a 24-word seed, 50 for a 12-word one. Keystrokes and the chaos grid
are not accepted, as their timing cannot be re-entered identically.

---

## Handling what it produces

**The `.txt` and `.pdf` exports are equivalent to your seed phrase.** They
contain the words, *and separately* the exact string that was hashed to create
them — either one rebuilds the wallet and spends the funds. Removing the word
list does not make them safe. Do not email them, sync them, or print them on a
shared printer.

The **`.enc`** export is encrypted with AES-256-GCM using a password you choose,
derived with PBKDF2-HMAC-SHA256 at 600,000 iterations. That is the one to keep on
a normal disk.

The **SeedQR** in the PDF is a scannable seed. Point only an offline signing
device at it — never a phone camera.

---

## What it implements

BIP-39 (English wordlist, 12 or 24 words) · BIP-32 · BIP-44 legacy · BIP-49
nested SegWit · BIP-84 native SegWit · BIP-86 Taproot · BIP-47 payment codes ·
BIP-352 silent payments · SLIP-132 extended keys · SeedSigner-format SeedQR.

Verified against `bitcoinjs-lib`, `bip39` and `bip32`: **235 of 235 assertions
matched exactly**, including published BIP-39, BIP-84, BIP-86 and BIP-47 test
vectors, across three mnemonics and three passphrases.

---

## Verifying a wallet you already have

The **Verify wallet** button checks that a paper backup, an `.enc` file, or a set
of dice/card notes still yields the same wallet. Use it before funding a new
wallet, and again whenever you want to confirm a backup is still good.

---

## What this tool does not protect you against

- **A compromised machine.** Malware with access to your browser can read the
  seed as it is generated. Work offline, on a machine you trust.
- **A compromised download.** Verify the checksum, from an independent source.
- **Your own backup.** Paper burns and steel gets lost. Test your backup by
  restoring it before you put real money behind it.
- **Shoulders and cameras.** The seed and the combined input string are both
  visible on screen.

---

## Known limitations

Stated plainly, because a wallet tool that hides these is not worth trusting:

- **Card entropy** assumes a genuine shuffle. The tool detects a *missing*
  reshuffle between rounds but cannot judge shuffle quality within one.
- **Chaos grid entropy** assumes your cell choices are close to uniform. Humans
  are imperfect randomisers, and a session this short cannot statistically verify
  it. A conservative discount is built in, but it is assumed rather than
  measured.
- **Grid timing and aim entropy** assumes the machine is not observing you.

`RELEASE-NOTES.md` has the full detail, including the security findings from the
v1.58 audit and what they mean for wallets made with earlier versions.

---

## License and provenance

Bundles `noble-secp256k1` (MIT) and `qrcode-generator` by Kazuhiko Arase (MIT),
both carrying their license notices inline, plus a RIPEMD-160 implementation that
carries no attribution comment in the source — check its provenance yourself if
that matters to you. The BIP-39 English wordlist is byte-identical to the
official list.
