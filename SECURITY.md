# Security Policy

AVBforge builds offline, single-file tools for Bitcoin key generation and encrypted communication (Amulet, TimeSeed, Sovereign Encryption, and related pages). Security reports are taken seriously and handled personally by the maintainer.

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

## Reporting a Vulnerability

Email: **security@avbforge.com**

Encrypt your report with PGP whenever possible:

- **Fingerprint:** `A624 7583 4D0C 4C51 2B96 D852 E02F 767A 48FA 7916`
- **Public key:** <https://avbforge.com/avbforge_0x48FA7916_public.asc>
- Also available on the OpenPGP keyserver network — search for the fingerprint above.

Please include as much of the following as you can:

- Which tool and exact version (e.g. `Amulet v1.58`, the version is in the page title of every file)
- Type of issue (e.g. weak entropy, biased key derivation, XSS, supply-chain, data exfiltration path)
- Step-by-step instructions to reproduce, or a proof of concept
- The impact as you assess it: what could an attacker gain, and under what conditions
- Whether the issue affects wallets or messages already generated with the tool

Reports in English or Dutch are both fine.

## What to Expect

- **Acknowledgement within 72 hours** of your report.
- A first assessment (accepted / needs more info / declined, with reasoning) within 7 days.
- A fix and coordinated disclosure target of **90 days** from acknowledgement. If a fix lands earlier, disclosure can move up; if the issue is unusually complex, I will propose a new date rather than go silent.
- You will be credited in the release notes if you wish (or kept anonymous — your choice).

There is currently no paid bug bounty program.

## Scope

In scope:

- All HTML tools published under avbforge.com and this repository, in their **latest released version** — including entropy collection, key/seed derivation, encryption code, and the offline guarantees the tools claim to make
- The build and delivery of those pages (integrity of published files, third-party code included in them)

Out of scope:

- Older versions superseded by a current release
- Vulnerabilities in browsers, operating systems, or hardware the tools run on
- Issues that require a compromised device (malware, keyloggers) — the threat model already assumes generation happens on a trusted, offline machine
- Denial of service, missing security headers on static pages, and other findings without a practical impact on key material or message confidentiality
- Social engineering of the maintainer or users

If you are unsure whether something is in scope, report it anyway — a false alarm is always preferred over a missed vulnerability.

## Supported Versions

Only the latest published version of each tool receives security fixes. Because the tools are single self-contained HTML files, updating means downloading the newest file; there is no migration.

## Safe Harbor

Good-faith security research on these tools is welcome. If you make a good-faith effort to comply with this policy — no data destruction, no privacy violations against third parties, no extortion, and reasonable time for a fix before public disclosure — I will not pursue legal action against you and will work with you openly. Testing is safest against your own local copies of the tools, which is exactly how they are meant to be used.
