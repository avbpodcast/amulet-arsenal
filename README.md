# AVBforge · Amulet Arsenal

Free, open-source Bitcoin and encryption tools. Each tool is a single HTML file that runs offline.
Live site: https://avbforge.com

- Security model (which tools go online, what is stored, limits): https://avbforge.com/security/
- Verify a download: https://avbforge.com/verify.html
- Source: https://codeberg.org/avbforge/pages (main), mirrored to https://github.com/avbpodcast/amulet-arsenal

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

## Security reports

Report problems privately to security@avbforge.com. See [SECURITY.md](SECURITY.md) for the policy.
Reports can be encrypted to the security key:

    avbforge <security@avbforge.com>
    ed25519 · fingerprint
    A624 7583 4D0C 4C51 2B96  D852 E02F 767A 48FA 7916

Public key: https://avbforge.com/0xE02F767A48FA7916_public.asc

## Mirrors

The Codeberg repository is the source. The GitHub repository is an automatic, read-only mirror:
commits made there are overwritten on the next sync, so please open issues and pull requests on Codeberg.
