# Amulet Wallet Generator

**Release Candidate 1 (version 1.51)**

A single offline web page that creates a fresh Bitcoin wallet on your own
computer. It rolls a brand new BIP-39 recovery phrase, shows you the wallet's
keys and first addresses, and lets you save a backup. Nothing leaves your
machine.

The current file is `amulet_1_51.html`. Each release keeps the previous file
next to it, so older versions are never overwritten.


## What it is, in one paragraph

When you create a Bitcoin wallet, everything depends on one secret: the
recovery phrase (also called the seed phrase or mnemonic). The Amulet Wallet
Generator produces that phrase using your computer's secure random generator,
optionally mixed with randomness you supply yourself, and then shows you the
public keys and addresses that follow from it. It is meant to be opened
offline, read once, and trusted only after you have looked at it.


## Before you trust it

This tool guards money, so treat it with suspicion until you are satisfied.

It is a single `.html` file. There is no installer and no background service.
It makes no network calls: you can open it with your internet disconnected,
or on a computer that has never been online, and it works exactly the same.

The whole program, including the word lists and the cryptography, is inside
that one file. Anyone who can read code can audit it. A matching
`hash_generator_v1.51.txt` file sits next to it: if you received this tool
from someone else, compare the SHA-256 hash of the `.html` file against that
record before you rely on it.

The safest way to use it is on an air-gapped computer: one that is offline
and ideally will never go online again.


## How to create a wallet

1. Copy the `.html` file to the offline computer and open it by
   double-clicking. Any modern browser will do.
2. Choose how long the recovery phrase should be. Twelve words is the common
   choice; twenty-four words is the longer, more conservative option.
3. Optionally add your own randomness. The generator already uses your
   computer's secure random generator on its own, which is enough by itself.
   On top of that you may, if you wish, contribute dice rolls, playing cards,
   keystrokes, or clicks on a chaos grid. Extra randomness can only ever add
   to the result; it can never weaken it.
4. Generate. The recovery phrase appears.
5. Write the words down, in order, on paper or stamped steel. Check them
   twice. This written copy is your wallet.


## The result screen

After generating, the page shows six sections.

**Seed phrase.** The recovery words themselves. A "Hide words" button blanks
them out so you can step away from the screen without exposing them.

**Seed fingerprint and SeedQR.** A short code and a small colour bar that act
as a quick visual identifier for this particular seed. Two different seeds
produce two different fingerprints, so you can tell wallets apart at a glance.
The same section holds the SeedQR, described further down.

**Entropy quality.** A plain-language read-out of how strong the randomness
was, including anything you contributed.

**Details.** The full record: the exact random inputs, the intermediate
hashes, and the checksum, so a careful reader can reproduce the phrase by
hand with any independent BIP-39 tool.

**Extended keys.** The public and private extended keys for the standard
address types, with their derivation paths. The public keys can be imported
into a watch-only wallet to monitor funds without exposing the seed.

**Preview addresses.** The first few receive addresses for each address type,
plus a Silent Payment address and a reusable Payment Code, so you can confirm
the wallet before funding it.


## The optional passphrase

Hidden behind a disclosure is a BIP-39 passphrase, sometimes called the
"25th word". It is an extra secret mixed into the seed. The same words with a
different passphrase produce a completely different wallet. Most people do not
use one. If you are not sure you want it, leave that box closed and empty.


## The SeedQR

The SeedQR is your recovery phrase encoded as a QR code, in the format used by
the SeedSigner offline signing device. Instead of typing every word by hand,
an offline signer can rebuild the wallet by scanning the code.

It sits behind a closed warning for a reason: that QR code is your seed.
Anyone who photographs or scans it can spend your coins. Reveal it only when
you mean to, scan it only with an offline signing device, and never point a
phone camera or an internet-connected webcam at it.


## Saving a backup

At the bottom of the result screen you can download the wallet report. Pick
one of four options:

- **All three files** (the default): the encrypted file plus both readable
  copies, downloaded one after another.
- **Encrypted** (`.enc`): the report sealed with a password you choose. This
  is the only format safe to keep on an everyday, online computer.
- **Plain text** (`.txt`): the full report as readable text.
- **PDF document** (`.pdf`): a printable report that also includes a SeedQR
  page, so a printed copy is a complete paper backup.

The `.txt` and `.pdf` files hold your seed in the clear, exactly like writing
it on paper. Keep them offline. The encrypted `.enc` file can be opened again,
and decrypted back to plain text, using the unlock tab on the start screen.


## Security, the short version

The recovery phrase is the money. Whoever holds it owns the coins.

Write it on paper or steel and store it offline. Do not store it digitally in
the clear, do not email it, do not photograph or screenshot it, and never type
it into a website, a search bar, or a chat. If you must keep a digital copy,
use the encrypted `.enc` export and a strong password.

When you are finished, the result screen has a button that wipes the seed and
keys from the browser tab. Use it, then close the tab.

Before you move real money in, confirm you can recover the wallet: take the
written words and restore them into a separate, trusted wallet, and check that
the first address matches the preview.


## What is under the hood

The recovery phrase is a standard BIP-39 mnemonic from the 2048-word English
list, with a valid checksum. The seed is derived per BIP-39, and the keys and
addresses per BIP-32, for the legacy, nested SegWit, native SegWit, and
Taproot address types (derivation paths `m/44'`, `m/49'`, `m/84'`, `m/86'`).
The encrypted export uses AES-256-GCM with a key stretched from your password
by PBKDF2.

Because it follows the public standards, a wallet made here can be restored in
any other standards-compliant wallet, and a wallet made elsewhere behaves the
same way here.


## Release Candidate 1

Version 1.50 was Release Candidate 1. It passed an eight-point smoke test with
no faults: the inline scripts all parse, the page loads cleanly, the BIP-39
seed matches the published TREZOR test vector, address derivation matches the
published BIP-44/49/84/86 test vectors, the SeedQR encodes correctly, the
fingerprint colour bar is deterministic, the PDF export produces a valid
document, and the "Hide words" toggle genuinely conceals the seed.

Version 1.51, the current file, is the same build with one small change: the
encrypted `.enc` backup now downloads under the exact filename that the
Amulet Scryer expects, so the watch-only import works without renaming.

A release candidate is a build believed to be ready, published so it can be
used and reviewed before being declared final. Please report anything that
looks wrong.
