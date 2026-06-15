# Amulet recovery fixtures — throwaway test data

Everything in this folder is deliberately public test data. The passwords
are printed below, the seed is the canonical BIP-39 test mnemonic, and no
real funds are or ever will be behind any of it. Its purpose: prove that
your copy of the recovery scripts works, BEFORE you need them in a real
emergency.

## The files

- `fixture-vault.zip` — a complete Amulet Vault backup (vault.meta +
  one wallet .enc + README). Master password and wallet password are both:
  `FIXTURE-throwaway-password-2026!`
- `amulet-share-fixture-1-of-3.amulet-share` (and -2, -3) — a 2-of-3
  Shamir split of that same vault, made with the Amulet Shamir Shared
  Split tool. Any 2 of the 3 recover the vault with NO password.
- `fixture-generator-report.enc` — an encrypted wallet report from the
  Amulet Wallet Generator (AMLT v2 binary format). Password:
  `Relic-test-password-123!`

## What a healthy recovery setup prints

1. `python3 amulet_relic.py verify`
   → "All vectors passed. Crypto stack is functional."

2. `python3 amulet_shamir_relic.py verify`
   → "All vectors passed. Recovery math is functional."

3. `python3 amulet_relic.py list <unzipped>/vault.meta`
   (password `FIXTURE-throwaway-password-2026!`)
   → one entry: `fixture wallet   w-fixture-0001.enc`

4. `python3 amulet_relic.py decrypt <unzipped>/w-fixture-0001.enc`
   (same password)
   → JSON containing the seed words `abandon abandon ... about`

5. `python3 amulet_shamir_relic.py amulet-share-fixture-1-of-3.amulet-share amulet-share-fixture-3-of-3.amulet-share`
   (no password!)
   → "Vault decrypted ... fixture wallet"

6. `python3 amulet_relic.py decrypt fixture-generator-report.enc`
   (password `Relic-test-password-123!`)
   → the full plaintext wallet report; seed phrase starts with
   `utility talent ranch section alley upon hold palm bike fade pelican actor`

If any step fails, do not trust that copy of the scripts: re-download and
compare the SHA-256 against the published SHA256SUMS.txt.

Dependencies: `pip install cryptography argon2-cffi`
(For air-gapped machines: run `pip download cryptography argon2-cffi` on an
online computer, carry the wheel files over, then
`pip install --no-index --find-links . cryptography argon2-cffi`.)
