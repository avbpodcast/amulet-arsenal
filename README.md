# AVBforge · Amulet Arsenal

Free, open-source Bitcoin and encryption tools. Each tool is a single HTML file that runs offline.
Live site: https://avbforge.com

## Verify

1. Download `amulet-arsenal.zip` from https://avbforge.com and unzip it.
2. Check every file: `sha256sum -c SHA256SUMS.txt` (Linux) or `shasum -a 256 -c SHA256SUMS.txt` (macOS).
   For Windows, see https://avbforge.com/verify.html.
3. Check the signature on the hash list:

       gpg --import .well-known/pgp-key.txt
       gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt

## AVBforge signing key

    avbforge <avbforge@nodes.be>
    ed25519 · fingerprint
    8781 57D4 1D9F B9BC D99B  1F81 1B35 6516 AFFC CEFE

Compare this fingerprint with the one printed by gpg. This README lives on Codeberg and the
site lives on a different host, so both would have to be compromised to fool you.
