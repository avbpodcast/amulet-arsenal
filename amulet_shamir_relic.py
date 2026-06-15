#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
amulet_shamir_relic.py v1.00 — independent recovery for Amulet Shamir backups.

If the Amulet Shamir Shared Split HTML tool is ever lost, tampered with, or
can't run in a browser you trust, your T-of-N Shamir backup remains fully
recoverable with nothing more than this short Python script plus T or more
shares. The math matches the HTML tool exactly: byte-wise Shamir secret
sharing over GF(2^8), Lagrange interpolation at x = 0, and AES-256-GCM for
the vault decryption. The recombined secret IS the vault's raw 32-byte
master key, so no password is needed.

Supported share inputs:
  * .amulet-share files (AMULET_SHAMIR_SHARE_V1 JSON). Self-contained:
    each file carries the encrypted vault zip inside, so T files alone
    recover everything. CRC32-checked. Field: GF(2^8), poly 0x11b
    (Rijndael), generator 0x03.
  * Amulet hex strings: 74 hex chars = 1 idx byte + 32 share bytes +
    4 CRC32 bytes. Same field as above. Needs --vault (the backup .zip
    or vault.meta) because hex shares carry only the key.
  * Coleman / secrets.js hex strings: "8" + 2-hex idx + share bytes.
    Field: GF(2^8), poly 0x11d, generator 0x02 (the field used by
    iancoleman.io/shamir and grempe/secrets.js). Needs --vault too.

NOT supported here: SLIP-0039 mnemonic shares (33 words). Those add a
Feistel cipher and RS1024 checksums on top; use the HTML tool, a
SLIP-0039 capable wallet (Trezor), or the python `shamir-mnemonic`
package (pip install shamir-mnemonic) to get back the 32-byte secret,
then pass it to this script with --raw-key.

What you get back:
  * The decrypted vault index (vault.meta payload): wallet names + files.
  * Optionally the embedded vault zip written to disk (--extract-zip),
    so the per-wallet .enc files can be decrypted with amulet_relic.py
    and their wallet passwords. (Wallet .enc files are encrypted with
    their own passwords, not with the master key — same as in the HTML.)

Dependencies:
  * Python 3.8+
  * cryptography >= 3.0     (pip install cryptography)
  (argon2-cffi is NOT needed here: shares bypass the password KDF.)

Commands:
  amulet_shamir_relic.py share1.amulet-share share2.amulet-share share3.amulet-share
  amulet_shamir_relic.py --hex 01ab..(74) --hex 02cd..(74) --vault backup.zip
  amulet_shamir_relic.py --raw-key <64 hex chars> --vault backup.zip
  amulet_shamir_relic.py ... --extract-zip recovered-vault.zip
  amulet_shamir_relic.py ... --out vault-index.json
  amulet_shamir_relic.py verify          Run built-in self-tests

Version history:
  v1.00  first release: .amulet-share files, Amulet hex, Coleman hex,
         --raw-key, vault.meta decryption (envelope v1 and v2), zip
         extraction, built-in self-tests.

License: public domain / CC0. Keep a copy next to your shares.
"""
from __future__ import annotations

__version__ = "1.00"

import argparse
import base64
import io
import json
import sys
import zipfile
import zlib
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.stderr.write(
        "amulet_shamir_relic requires the 'cryptography' package.\n"
        "Install with:   pip install cryptography\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic — two fields, matching the HTML tool exactly.
#
# Amulet field: poly 0x11b (Rijndael, x^8+x^4+x^3+x+1). 0x11b is irreducible
# but not primitive, so the exp/log tables iterate by multiplication with
# alpha+1 (0x03), exactly like the JS: x ^= (x << 1) ^ (x & 0x80 ? 0x1b : 0).
#
# Coleman field: poly 0x11d (x^8+x^4+x^3+x^2+1), primitive, generator 0x02,
# exactly like the JS: x = (x << 1) ^ (x & 0x80 ? 0x1d : 0).
# ---------------------------------------------------------------------------
def _build_tables(primitive: bool) -> Tuple[list, list]:
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        if primitive:                      # 0x11d, generator 0x02
            x = ((x << 1) ^ (0x1D if x & 0x80 else 0)) & 0xFF
        else:                              # 0x11b, generator 0x03
            x = (x ^ (x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_EXP_AMULET, _LOG_AMULET = _build_tables(primitive=False)
_EXP_COLEMAN, _LOG_COLEMAN = _build_tables(primitive=True)


def _gf_mul(a: int, b: int, exp: list, log: list) -> int:
    if a == 0 or b == 0:
        return 0
    return exp[log[a] + log[b]]


def _gf_div(a: int, b: int, exp: list, log: list) -> int:
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("Shamir: division by zero")
    return exp[(255 + log[a] - log[b]) % 255]


def shamir_combine(shares: List[Tuple[int, bytes]], field: str = "amulet") -> bytes:
    """Lagrange interpolation at x = 0, byte-wise. shares = [(idx, bytes), ...]"""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    exp, log = (_EXP_AMULET, _LOG_AMULET) if field == "amulet" else (_EXP_COLEMAN, _LOG_COLEMAN)
    length = len(shares[0][1])
    seen = set()
    for idx, data in shares:
        if len(data) != length:
            raise ValueError("share length mismatch")
        if idx in seen:
            raise ValueError(f"duplicate share index {idx}")
        if not (1 <= idx <= 255):
            raise ValueError(f"bad share index {idx}")
        seen.add(idx)
    out = bytearray(length)
    for byte_i in range(length):
        secret = 0
        for i, (xi, yi_bytes) in enumerate(shares):
            yi = yi_bytes[byte_i]
            num = den = 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                num = _gf_mul(num, xj, exp, log)
                den = _gf_mul(den, xi ^ xj, exp, log)
            secret ^= _gf_mul(yi, _gf_div(num, den, exp, log), exp, log)
        out[byte_i] = secret
    return bytes(out)


def shamir_split(secret: bytes, threshold: int, total: int,
                 field: str = "amulet", _rand=None) -> List[Tuple[int, bytes]]:
    """Mirror of the HTML's shamirSplit (used by the self-test)."""
    import os
    if _rand is None:
        _rand = os.urandom
    if not (2 <= threshold <= 16) or not (threshold <= total <= 16):
        raise ValueError("threshold must be 2..16 and <= total <= 16")
    exp, log = (_EXP_AMULET, _LOG_AMULET) if field == "amulet" else (_EXP_COLEMAN, _LOG_COLEMAN)
    out = [(i, bytearray(len(secret))) for i in range(1, total + 1)]
    for byte_i, sb in enumerate(secret):
        coeffs = bytes([sb]) + _rand(threshold - 1)
        for idx, buf in out:
            # Horner evaluation of the polynomial at x = idx
            y = 0
            for c in reversed(coeffs):
                y = _gf_mul(y, idx, exp, log) ^ c
            buf[byte_i] = y
    return [(i, bytes(b)) for i, b in out]


# ---------------------------------------------------------------------------
# Share parsing — mirrors of the HTML's parsers, CRC checks included.
# ---------------------------------------------------------------------------
def crc32_hex(data: bytes) -> str:
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


def parse_share_file(path: Path) -> dict:
    """Parse + CRC-check one .amulet-share file."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    if obj.get("magic") != "AMULET_SHAMIR_SHARE_V1":
        raise ValueError(f"{path.name}: not an AMULET_SHAMIR_SHARE_V1 file")
    share_bytes = bytes.fromhex(obj["share"])
    zip_bytes = base64.b64decode(obj["vaultZip"]) if obj.get("vaultZip") else b""
    body = bytes([obj["idx"]]) + share_bytes + zip_bytes
    if obj.get("crc") and crc32_hex(body) != str(obj["crc"]).lower():
        raise ValueError(f"{path.name}: checksum failed (file corrupted?)")
    return {
        "idx": int(obj["idx"]), "share": share_bytes, "zip": zip_bytes,
        "T": int(obj["T"]), "N": int(obj["N"]),
        "backupId": obj.get("backupId"), "label": obj.get("label"),
        "name": path.name,
    }


def parse_hex_share(text: str) -> Tuple[str, int, bytes]:
    """Returns (field, idx, share). Amulet 74-char or Coleman '8…' format."""
    t = "".join(str(text).split()).lower()
    if len(t) == 74:                       # Amulet: idx(1) + share(32) + crc(4)
        raw = bytes.fromhex(t)
        body, crc = raw[:33], raw[33:]
        if zlib.crc32(body) & 0xFFFFFFFF != int.from_bytes(crc, "big"):
            raise ValueError("Amulet hex share checksum mismatch (typo somewhere?)")
        idx = body[0]
        if not (1 <= idx <= 16):
            raise ValueError(f"bad share index {idx}")
        return "amulet", idx, body[1:]
    if t.startswith("8") and len(t) >= 7:  # Coleman / secrets.js
        idx = int(t[1:3], 16)
        if not (1 <= idx <= 255):
            raise ValueError("bad share idx in Coleman share")
        data = t[3:]
        if len(data) % 2:
            raise ValueError("Coleman share data is not a whole number of bytes")
        return "coleman", idx, bytes.fromhex(data)
    raise ValueError(
        "Unrecognized hex share. Amulet: 74 hex chars. "
        "Coleman / secrets.js: starts with '8'."
    )


# ---------------------------------------------------------------------------
# Vault decryption with the recombined raw key (no KDF, no password).
# ---------------------------------------------------------------------------
def canonical_envelope_aad(env: dict) -> bytes:
    """Identical to amulet_relic.py / the Vault's JS canonicalEnvelopeAad()."""
    kdf = env["kdf"]
    ordered = {
        "v": env["v"],
        "type": env["type"],
        "kdf": {"name": kdf["name"], "m": kdf["m"], "t": kdf["t"],
                "p": kdf["p"], "salt": kdf["salt"]},
        "iv": env["iv"],
    }
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def decrypt_meta_with_key(meta_bytes: bytes, master_key: bytes) -> dict:
    env = json.loads(meta_bytes.decode("utf-8"))
    if env.get("type") != "amulet-vault-meta":
        raise ValueError("not an Amulet vault.meta file")
    iv = base64.b64decode(env["iv"])
    ct = base64.b64decode(env["ct"])
    version = env.get("v", 1)
    aad = canonical_envelope_aad(env) if version >= 2 else None
    try:
        pt = AESGCM(master_key).decrypt(iv, ct, aad)
    except InvalidTag:
        raise ValueError(
            "Decryption failed. The shares do not match this backup, "
            "or the backup is corrupted."
        )
    payload = json.loads(pt.decode("utf-8"))
    if payload.get("magic") != "AMULET_VAULT_V1":
        raise ValueError(f"unexpected payload magic: {payload.get('magic')!r}")
    return payload


def meta_bytes_from_vault_arg(vault_path: Path) -> bytes:
    data = vault_path.read_bytes()
    if data[:2] == b"PK":                  # backup zip
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                if name.split("/")[-1] == "vault.meta":
                    return z.read(name)
        raise ValueError(f"{vault_path.name}: zip contains no vault.meta")
    return data                            # assume it IS vault.meta


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------
def cmd_verify() -> int:
    ok = True

    def check(name, fn):
        nonlocal ok
        try:
            fn()
            print(f"  [  OK  ] {name}")
        except Exception as e:           # noqa: BLE001
            ok = False
            print(f"  [ FAIL ] {name}: {e}")

    def t_roundtrip_amulet():
        secret = bytes(range(1, 33))
        shares = shamir_split(secret, 3, 5, "amulet")
        for subset in ([0, 1, 2], [1, 3, 4], [0, 2, 4], [1, 2, 3, 4]):
            got = shamir_combine([shares[i] for i in subset], "amulet")
            assert got == secret, "recombined secret differs"

    def t_roundtrip_coleman():
        secret = bytes(range(1, 33))
        shares = shamir_split(secret, 2, 3, "coleman")
        for subset in ([0, 1], [1, 2], [0, 2]):
            got = shamir_combine([shares[i] for i in subset], "coleman")
            assert got == secret, "recombined secret differs"

    def t_below_threshold_differs():
        import os
        secret = os.urandom(32)
        shares = shamir_split(secret, 3, 5, "amulet")
        got = shamir_combine(shares[:2], "amulet")
        assert got != secret, "2 of 3 shares must NOT reveal the secret"

    def t_field_tables():
        # multiplicative sanity: a * a^-1 == 1 for every nonzero a, both fields
        for exp, log in ((_EXP_AMULET, _LOG_AMULET), (_EXP_COLEMAN, _LOG_COLEMAN)):
            for a in range(1, 256):
                inv = exp[(255 - log[a]) % 255]
                assert _gf_mul(a, inv, exp, log) == 1

    def t_hex_share_roundtrip():
        secret = bytes(range(32, 0, -1))
        shares = shamir_split(secret, 2, 2, "amulet")
        lines = []
        for idx, sh in shares:
            body = bytes([idx]) + sh
            lines.append(body.hex() + format(zlib.crc32(body) & 0xFFFFFFFF, "08x"))
        parsed = [parse_hex_share(l) for l in lines]
        assert all(f == "amulet" for f, _, _ in parsed)
        got = shamir_combine([(i, s) for _, i, s in parsed], "amulet")
        assert got == secret

    def t_gcm_roundtrip():
        import os
        key, iv = os.urandom(32), os.urandom(12)
        env = {"v": 2, "type": "amulet-vault-meta",
               "kdf": {"name": "Argon2id", "m": 262144, "t": 2, "p": 1,
                       "salt": base64.b64encode(os.urandom(16)).decode()},
               "iv": base64.b64encode(iv).decode()}
        payload = json.dumps({"magic": "AMULET_VAULT_V1", "wallets": []}).encode()
        ct = AESGCM(key).encrypt(iv, payload, canonical_envelope_aad(env))
        env["ct"] = base64.b64encode(ct).decode()
        meta = json.dumps(env).encode()
        out = decrypt_meta_with_key(meta, key)
        assert out["magic"] == "AMULET_VAULT_V1"

    print("amulet_shamir_relic self-test")
    print("=" * 78)
    check("GF(2^8) tables, both fields (a * a^-1 == 1 for all a)", t_field_tables)
    check("Amulet-field 3-of-5 split/combine round-trip", t_roundtrip_amulet)
    check("Coleman-field 2-of-3 split/combine round-trip", t_roundtrip_coleman)
    check("below-threshold shares do not reveal the secret", t_below_threshold_differs)
    check("Amulet 74-char hex share encode/parse/CRC round-trip", t_hex_share_roundtrip)
    check("raw-key AES-GCM vault.meta round-trip (v=2 AAD)", t_gcm_roundtrip)
    print("=" * 78)
    print("All vectors passed. Recovery math is functional." if ok
          else "ONE OR MORE VECTORS FAILED — do not trust this copy.")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="amulet_shamir_relic.py",
        description="Recombine Amulet Shamir shares and decrypt the vault "
                    "they protect. Run with 'verify' to self-test.",
    )
    ap.add_argument("shares", nargs="*",
                    help=".amulet-share files (T or more), or the word 'verify'")
    ap.add_argument("--hex", action="append", default=[],
                    help="hex share string (repeatable; Amulet 74-char or Coleman)")
    ap.add_argument("--raw-key",
                    help="skip recombination: 64 hex chars of the master key "
                         "(e.g. from a SLIP-0039 tool)")
    ap.add_argument("--vault",
                    help="backup .zip or vault.meta (needed for hex / raw-key input)")
    ap.add_argument("--extract-zip", metavar="OUT.zip",
                    help="write the embedded vault zip here (self-contained shares only)")
    ap.add_argument("--out", metavar="OUT.json",
                    help="write the decrypted vault index JSON here")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if args.shares == ["verify"]:
        return cmd_verify()

    zip_bytes = b""
    master_key = None

    if args.raw_key:
        master_key = bytes.fromhex(args.raw_key)
        if len(master_key) != 32:
            sys.stderr.write("--raw-key must be 64 hex characters (32 bytes)\n")
            return 1
    elif args.shares:
        parsed = [parse_share_file(Path(p)) for p in args.shares]
        ids = {p["backupId"] for p in parsed}
        if len(ids) > 1:
            sys.stderr.write(
                f"These shares belong to DIFFERENT backups (ids: {sorted(ids)}).\n"
                "Mixing them cannot work; use shares from one backup only.\n")
            return 1
        T = parsed[0]["T"]
        if len(parsed) < T:
            sys.stderr.write(
                f"Not enough shares: this is a {T}-of-{parsed[0]['N']} backup "
                f"and you provided {len(parsed)}. Any {T} shares will do.\n")
            return 1
        print(f"[shamir_relic] {len(parsed)} shares, backup "
              f"'{parsed[0]['label']}' ({T}-of-{parsed[0]['N']}), CRC OK",
              file=sys.stderr)
        master_key = shamir_combine([(p["idx"], p["share"]) for p in parsed], "amulet")
        zip_bytes = next((p["zip"] for p in parsed if p["zip"]), b"")
    elif args.hex:
        triples = [parse_hex_share(h) for h in args.hex]
        fields = {f for f, _, _ in triples}
        if len(fields) > 1:
            sys.stderr.write("Cannot mix Amulet and Coleman hex shares: "
                             "they use different GF(2^8) fields.\n")
            return 1
        master_key = shamir_combine([(i, s) for _, i, s in triples], fields.pop())
        print(f"[shamir_relic] {len(triples)} hex shares recombined", file=sys.stderr)
    else:
        ap.print_help()
        return 1

    # locate vault.meta
    if args.vault:
        meta_bytes = meta_bytes_from_vault_arg(Path(args.vault))
    elif zip_bytes:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            names = [n for n in z.namelist() if n.split("/")[-1] == "vault.meta"]
            if not names:
                sys.stderr.write("Embedded zip contains no vault.meta.\n")
                return 1
            meta_bytes = z.read(names[0])
    else:
        sys.stderr.write(
            "No vault to decrypt: hex / raw-key input carries only the key.\n"
            "Add --vault <backup.zip or vault.meta>.\n")
        return 1

    payload = decrypt_meta_with_key(meta_bytes, master_key)

    wallets = payload.get("wallets", [])
    print(f"\nVault decrypted. Created {payload.get('createdAt', '?')}, "
          f"{len(wallets)} entr{'y' if len(wallets) == 1 else 'ies'}:")
    for w in wallets:
        print(f"  - {w.get('name', '?'):<30} {w.get('file', '')}")
    print("\nEach wallet .enc file is encrypted with its OWN wallet password.")
    print("Decrypt them with:  python3 amulet_relic.py decrypt <file.enc>")

    if args.out:
        Path(args.out).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Vault index written to {args.out}")
    if args.extract_zip:
        if not zip_bytes:
            sys.stderr.write("--extract-zip: no embedded zip available "
                             "(only self-contained .amulet-share files carry one).\n")
            return 1
        Path(args.extract_zip).write_bytes(zip_bytes)
        print(f"Embedded vault zip written to {args.extract_zip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
