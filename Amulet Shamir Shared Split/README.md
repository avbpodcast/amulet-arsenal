# Amulet Shamir Shared Split

A fork of the Amulet Vault tool that adds Shamir Shared Split as the
differentiating feature: a vault's master key can be split into N shares
with a T-of-N recovery threshold, so any T of N shares can put the vault
back together without the master password. Fewer than T shares reveal
nothing about the key.

This is a separate variant of Amulet Vault, not a replacement. It exists
in its own folder so the upstream Vault stays unchanged while this tool
iterates.

## What it does (v0.11)

Two lanes on the landing screen.

**Split a vault into shares.** Pick a vault `.zip` backup (or use a vault
already open on the page), unlock it once with the master password, then
choose the threshold (T and N from 2 to 16, T ≤ N; common picks 2-of-3,
3-of-5, 4-of-7) and the share format:

- **Self-contained `.amulet-share` files** (recommended) — each share file
  carries the full encrypted vault inside, so any T files alone reassemble
  the vault; no separate backup needed. The "I have all my shares" button
  stays locked until every share has been downloaded at least once.
- **SLIP-0039 mnemonic words** — 33 words per share, Trezor-compatible.
- **Hex shares** — 74-character paper-friendly strings (Amulet or
  secrets.js flavour).

**Reassemble shares back into a vault.** Drop T or more `.amulet-share`
files (nothing else needed), or paste SLIP-0039 mnemonics / hex shares
together with a vault `.zip` backup or `vault.meta` (those formats carry
only the master key). The page rebuilds the master key, decrypts the
vault, and offers to open it in place, save it to a folder, or download
it as a fresh `.zip`. No password is needed at reassembly.

## Files

- `amulet_shamir_shared_split_v0.11.html` — the tool, single-file HTML.
- `hash_amulet_shamir_shared_split_v0.11.txt` — SHA-256 of the above.

On the published site only the current tool, its hash file and this README
ship; the audit-copy bundles (`amulet-crypto-bundle.js`,
`argon2-bundle.extracted.js`, `slip39-bundle.js`) live in the source
repository, and older versions sit under `archive/`.

## Versioning

Same convention as the rest of the Amulet family. Filename and the
internal version stamp are bumped by 0.01 per substantive change. Every
released version stays on disk; old versions are not overwritten.

## Status

v0.11 (beta): splitting and reassembly work end-to-end for all three
share formats. Vaults opened or reassembled here stay compatible with
the upstream Amulet Vault.

## Source provenance

Forked from Amulet Vault v1.50. All inlined / audit-copy bundles are
byte-identical copies of the parent Vault's bundles, plus a SLIP-0039
bundle for the mnemonic share format.
