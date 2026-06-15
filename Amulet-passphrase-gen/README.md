# Amulet Passphrase Word Picker

A standalone, offline HTML tool that draws random words from a pool of **10,000 unique words** to help you build strong passphrases. One file, no installation, no network access — open it in any modern browser.

## Overview

Click **Pick a word** and the tool draws one word uniformly at random from a combined dictionary of 10,000 words. Draw as many as you need; the words accumulate into a passphrase you can copy. Every draw uses your browser's cryptographically secure random number generator, and a live strength meter shows exactly how much entropy you have accumulated.

The tool is fully self-contained: all 10,000 words are embedded in the HTML file itself. It makes no network requests and works with no internet connection, which makes it suitable for air-gapped or offline use.

## Quick start

1. Open `Amulet Picker v16.html` in a browser (double-click the file).
2. Click **Pick a word** once for each word you want, or click **Auto-pick** to have it draw a full passphrase for you.
3. *(Optional)* Enter a **session pepper** for defense-in-depth — see below.
4. Click **Copy passphrase** to copy the result. The clipboard auto-clears after 45 seconds.
5. Click **Clear** to wipe the passphrase from the screen and clipboard when you are done.

## The word pool

The pool is 10,000 unique words, fully de-duplicated, combined from four sources:

| Source | Words | Notes |
|---|---|---|
| BIP39 | 2,048 | The standard Bitcoin mnemonic word list |
| EFF Diceware (large) | 6,906 | EFF's long word list, minus entries already in BIP39 |
| Custom | 946 | A personal word list, minus entries already counted above |
| Extra | 100 | 50 biology terms, 46 archaic / Old English words, 4 hand-picked |
| **Total** | **10,000** | every word distinct, case-insensitively |

De-duplication uses the priority order BIP39 > EFF > Custom > Extra: a word that appears in more than one source is counted once, under its highest-priority source. The original three lists together held 10,864 entries with 964 cross-list duplicates; collapsing those left 9,900 unique words, and 100 new words were added to reach exactly 10,000.

The 100 "Extra" words are 50 biology terms (e.g. *ribosome*, *chloroplast*, *tardigrade*), 46 archaic or Old English words (e.g. *gloaming*, *forsooth*, *eldritch*), and 4 hand-picked additions: *ghouli*, *sabrosito*, *wiedersehen*, *geryon*. They are listed in `extra_wordlist.txt`.

A note on data integrity: the BIP39 source file contained `FALSE` in uppercase (a spreadsheet auto-correction artifact). This was corrected to lowercase `false`, matching the canonical BIP39 list.

## How the randomness works

Each draw is a uniform, independent choice of one word out of 10,000.

- **Random source.** All randomness comes from `crypto.getRandomValues`, the browser's cryptographically secure RNG. The tool never falls back to `Math.random()`. If no secure RNG is available, it disables itself rather than degrading silently.
- **Unbiased selection.** A naive `random % 10000` would introduce modulo bias. Instead the tool reads 14-bit values and rejection-samples — any value of 10000 or higher is discarded and re-drawn — so every word has exactly equal probability.
- **Entropy per word.** A uniform choice among 10,000 words carries log2(10000) = **13.2877 bits** of entropy. This is the theoretical maximum for a 10,000-word list.

Because draws are independent and made with replacement, the same word *can* appear twice in one passphrase. This does not weaken anything: each draw still contributes a full 13.29 bits.

| Words | Entropy | Strength rating |
|---|---|---|
| 3 | 39.9 bits | Very weak |
| 4 | 53.2 bits | Weak |
| 5 | 66.4 bits | Fair |
| 6 | 79.7 bits | Strong |
| 7 | 93.0 bits | Strong |
| 8 | 106.3 bits | Very strong |
| 10 | 132.9 bits | Excellent |

## The optional session pepper (defense-in-depth)

The pepper is an optional secret you type into the tool. It does **not** add entropy — a uniform pick of 1-in-10,000 is already entropy-maximal — but it adds *robustness* by removing a single point of failure.

Without a pepper, 100% of a passphrase's secrecy rests on `crypto.getRandomValues`. With a pepper set, word selection becomes:

```
sessionKey = PBKDF2-HMAC-SHA256(pepper, sessionSalt, 200,000 iterations)
wordIndex  = HMAC-SHA256(sessionKey, counter + 32 fresh CSPRNG bytes)  ->  rejection-sampled
```

Fresh random bytes are mixed in on every single draw, so the output stays uniform and **non-reproducible**. The security benefit: an attacker who somehow fully predicted the browser's RNG still could not reconstruct your words without also knowing your pepper. Your passphrase stays secret as long as **either** the RNG **or** the pepper is unknown to the attacker.

Other details:

- **The session salt is real.** It is a random 16-byte value used as the PBKDF2 salt, so it genuinely changes the derived key. Two sessions with the same pepper but different salts produce independent word streams. The salt is shown in the interface and can be regenerated with the ↻ button.
- **The pepper is never stored.** It lives only in the input field for the current session.
- **It needs a secure context.** The pepper relies on `crypto.subtle` (Web Crypto). Opening the file locally (`file://`) qualifies, as does `https://`. Over plain remote `http://` the pepper feature disables itself and the picker falls back to CSPRNG-only.

Important: this is the *defense-in-depth* design, not a deterministic "brainwallet" generator. Because fresh randomness is mixed into every draw, **the pepper cannot be used to regenerate a previous passphrase.** It protects future draws; it does not reproduce past ones.

## Passphrase strength meter

A live meter below the card shows the current word count, the cumulative entropy in bits, and a plain-language rating that updates with every draw. The ratings are: Very weak (< 44 bits), Weak (< 60), Fair (< 78), Strong (< 100), Very strong (< 128), Excellent (≥ 128). The pepper does not change this readout — it reflects the genuine, honest entropy of the word draws only.

## Self-test and verification

The **Show self-test & verification** panel checks the parts of the generator that *can* be checked, against the actual mechanism:

- a secure RNG is present;
- the word pool is intact — 10,000 entries, 0 duplicates;
- the selection is uniform — a live chi-square test over 25,000 draws (or 200,000 with **Run full verification**) of the real rejection sampler;
- the live picker path, including HMAC pepper mixing, is uniform — 5,000 real draws (full verification only);
- the device's raw RNG output is statistically balanced.

The panel is honest about its scope: it confirms that a secure RNG is present and that the selection algorithm is unbiased, but it does **not** re-prove the cryptographic quality of the browser/OS RNG itself — no in-page test can do that, and any tool claiming otherwise is misleading you.

## Clipboard auto-clear

When you copy a passphrase, the tool shows a 45-second countdown and then overwrites the clipboard with blank text. If the page is not focused when the timer fires, it retries on the next click. Clicking **Clear** also clears the clipboard immediately.

Caveat: this overwrites the *current* clipboard contents, but it cannot erase operating-system clipboard history (for example, Windows Clipboard History or a third-party clipboard manager). Those are separate stores outside any web page's reach.

## Security model and honest caveats

- **A pepper adds robustness, not entropy.** The per-word entropy is fixed at 13.29 bits regardless of the pepper.
- **No deterministic regeneration.** The defense-in-depth pepper cannot reproduce a past passphrase. Deterministic generation was deliberately not built, because it would make the passphrase only as strong as the pepper itself (the classic "brainwallet" weakness).
- **Memory cannot be truly wiped.** JavaScript strings are immutable and garbage-collected, so a drawn word cannot be forcibly zeroed from memory. The **Clear** button does the best achievable: it wipes the screen, the card, the source readout, and the pending clipboard, and drops its references.
- **Clipboard history persists.** See the clipboard section above.
- **Trust in the RNG.** The tool's security ultimately rests on `crypto.getRandomValues` (and, with a pepper, additionally on your pepper). The verification panel cannot prove the RNG is sound; it can only confirm one is present and that selection is unbiased.

## Offline / standalone use

The HTML file is completely self-contained — all 10,000 words and all code are embedded, with no external scripts, fonts, or network calls. For sensitive passphrases, the recommended use is to open it on an offline or air-gapped machine. You can confirm the absence of network activity in your browser's developer tools.

## Files in this project

- `Amulet Picker v16.html` — the current tool (open this one)
- `Amulet Picker v1.html` … `v15.html` — earlier versions, kept for reference

On the published site only the current tool, its hash file and this README
are included; the source word lists above live in the source repository, and
older versions sit under `archive/`.
- `BIP39-searcheable.txt` — BIP39 source word list (with `FALSE` corrected to `false`)
- `eff_large_wordlist.txt` — EFF large Diceware source word list
- `1040wordlist_manuwordlist.txt` — the custom personal source word list
- `extra_wordlist.txt` — the 100 added words (biology, archaic, hand-picked)
- `README.md` — this file

## Version history

- **v1** — Initial standalone picker. Three lists (BIP39, EFF, Custom), 10,864 entries including cross-list duplicates.
- **v2** — De-duplicated to exactly 10,000 unique words; added the 100 "Extra" words; corrected `FALSE` to `false` in the BIP39 source; introduced the four-way source tagging.
- **v3** — Fixed the Clear bug (the last drawn word stayed visible after Clear); fixed a latent edge-case bug in the rejection sampler; added a fail-closed check for the secure RNG; relabeled the inherited cosmetic "salt" and self-test honestly.
- **v4** — Replaced the cosmetic self-test with genuine verification of the real picker; added the live entropy strength meter; added 45-second clipboard auto-clear; removed the non-functional decorative salt and batch logic.
- **v5** — Added the optional session pepper: a PBKDF2-derived key HMAC-mixed into every draw for defense-in-depth, with a genuine load-bearing session salt.
- **v6** — Visual redesign in the M-Vault theme (warm paper, oxblood accent, serif headings, monospace metadata, flat sharp-cornered components); responsive layout for desktop and mobile; light/dark theme toggle; the verification report restructured from a cramped monospace block into a clean, readable list of check rows.
- **v7** — Added **Auto-pick**: a button that draws words one after another, like a user clicking repeatedly, until the passphrase reaches at least "Very strong" (8 words, ~106 bits). It clears any current passphrase first, so each press produces a fresh one.
- **v8** — Added **Add extra**: a button that appends a short, cryptographically-random garnish of digits and symbols (2 of each, shuffled) to satisfy sites that demand a number and a special character. The extra re-rolls rather than stacks on repeat clicks and is removable by clicking it.
- **v9** — The **Add extra** characters are now sprinkled into random gaps between the words and at the end (never inside a word), and because they are genuinely random, the strength meter now counts the real entropy they contribute (about 13.3 bits for the four characters) — words still provide the bulk of it. The brand-bar tag was corrected from the inaccurate "Diceware" to "BIP39 + EFF + more".
- **v10** — Added a **word-list integrity check** to the verification panel: a SHA-256 of the 10,000 words is baked into the file at build time and re-verified on demand, catching corruption or casual tampering (with an honest note that a determined tamperer could rewrite the checksum too). Also added a Memory hook feature (later removed in v11).
- **v11** — Removed the Memory hook. Added a **passphrase fingerprint**: a 16-character hex code (grouped, e.g. `D14F-DD6E-D39D-D51E`) and a small symmetric glyph, both derived from the SHA-256 of the full passphrase and shown live whenever a passphrase exists. It is a checksum for backups — record it next to the passphrase, and re-typing the passphrase here later must reproduce the identical fingerprint, so a single transcription error (a misread `l`/`1` or `0`/`O`) is caught immediately.
- **v12** — Added a **Verify an existing passphrase** panel: paste or type a passphrase you already hold and the tool shows its fingerprint (to compare against the one you recorded) and validates each word against the 10,000-word pool — flagging mistyped words so a transcription error can be pinpointed. Whitespace is normalised to match how the tool writes passphrases, so a generated passphrase verified back yields the identical fingerprint.
- **v13** — The Verify panel gained an optional **Expected fingerprint** field: enter the fingerprint you recorded and the tool immediately reports `MATCH` or `NO MATCH` against the one it regenerates from the entered passphrase. The comparison is format-forgiving (case, hyphens and spaces are ignored) and shows an "incomplete" state until 16 hex characters are entered.
- **v14** — Added a note for standalone use: the Picker's output plugs straight into Amulet Vault as a master passphrase, with matching visual styling.
- **v15** — **Fingerprint scheme changed**, shared with Amulet Vault v1.72: the fingerprint is now SHA-256 of an Argon2id run over the passphrase (fixed public salt, 256 MiB memory cost) instead of a plain SHA-256. A recorded fingerprint is therefore no cheaper to attack than the passphrase itself. It computes on a button press (about a second per run). **Fingerprints recorded with v14 or earlier no longer match v15+.**
- **v16** — Race-condition guard: if the passphrase changes while a fingerprint is still being computed, the stale result is discarded instead of being shown for the wrong phrase.

## Credits

The cryptographically secure random core (rejection sampling over `crypto.getRandomValues`) is adapted from *BIP39 Raffle v2.8*. Word lists: the BIP39 standard list, the Electronic Frontier Foundation's large Diceware list, a custom personal list, and 100 hand-curated additions.
