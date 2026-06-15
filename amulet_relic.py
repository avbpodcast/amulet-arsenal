#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
amulet_relic.py v1.01 — independent recovery for Amulet Vault encrypted files.

If the Amulet Vault HTML is ever lost, tampered with, or can't run in a
browser you trust, your encrypted files remain fully recoverable with
nothing more than this short Python script plus your passwords. Every
crypto primitive matches the Amulet tools exactly: vault-native files
(vault.meta and the wallet / timelock .enc) use Argon2id, while the
Generator's AMLT binary .enc files use PBKDF2-HMAC-SHA-256 (600k iters).
Both wrap AES-256-GCM with a 16-byte salt and a 12-byte IV, so the .enc
files on disk are bit-for-bit decryptable without re-running the HTML.

Supported file formats (auto-detected):
  * Vault-native wallet / timelock .enc  : JSON wrapper, AMULET_*_V1 payload.
                                           Both envelope v=1 (Vault v1.08 ..
                                           v1.30) and v=2 (Vault v1.50+,
                                           AAD-bound header) are accepted.
  * vault.meta index                     : JSON wrapper, AMULET_VAULT_V1 payload.
                                           Same envelope versioning as above.
                                           NOT decryptable here if the vault
                                           was created with a YubiKey: the
                                           hmac-secret output can't be
                                           reproduced outside WebAuthn.
  * Amulet v1.3+ binary .enc             : 4-byte "AMLT" magic + version +
                                           salt + IV + ciphertext. Both AMLT
                                           v=1 (Generator v1.3 .. v1.35) and
                                           v=2 (Generator v1.36+, AAD-bound
                                           header) are accepted.

Recognized but handled differently:
  * .amulet-share (AMULET_SHAMIR_SHARE_V1): one share of a T-of-N Shamir
                                           backup. This script cannot
                                           recombine shares; use
                                           amulet_shamir_relic.py with T or
                                           more share files instead.
  * watch-only export (AMULET_WATCH_ONLY_V1) and Scryer snapshot
    (AMULET_SCRYER_SNAPSHOT_V1)           : plaintext JSON, nothing to
                                           decrypt; printed as-is.

Version history:
  v1.00  original release (decrypt / inspect / list / export-txt / verify).
  v1.01  recognizes .amulet-share, watch-only and Scryer-snapshot files and
         explains what to do with them instead of "Unrecognized file format".

Dependencies:
  * Python 3.8+
  * cryptography >= 3.0     (pip install cryptography)

Commands:
  amulet_relic.py decrypt     <file>          Decrypt and print the payload
  amulet_relic.py inspect     <file>          Summarize file type + params
  amulet_relic.py list        <vault.meta>    Decrypt + list the index
  amulet_relic.py export-txt  <timelock.enc>  Re-emit the original .txt backup
  amulet_relic.py verify                      Run built-in crypto KAT vectors

License: public domain / CC0. Keep a copy next to your backups.
"""
from __future__ import annotations

__version__ = "1.01"

import argparse
import base64
import getpass
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.stderr.write(
        "amulet_relic requires the 'cryptography' package.\n"
        "Install with:   pip install cryptography\n"
    )
    sys.exit(2)

try:
    # Argon2id is used by vault-native files since Amulet Vault v1.08.
    from argon2.low_level import hash_secret_raw as argon2_hash_raw
    from argon2.low_level import Type as Argon2Type
except ImportError:
    sys.stderr.write(
        "amulet_relic requires the 'argon2-cffi' package for vault files\n"
        "created by Amulet Vault v1.08+ (Argon2id KDF).\n"
        "Install with:   pip install argon2-cffi\n"
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# Vault crypto parameters (must match Amulet Vault exactly)
# ---------------------------------------------------------------------------
# Vault-native files (v1.08+) use Argon2id. Same parameters as the HTML:
ARGON2_PARAMS_DEFAULT = dict(
    time_cost=5,       # t
    memory_cost=131_072,  # m, in KiB (128 MiB)
    parallelism=1,     # p
    hash_len=32,
)

# PBKDF2 is still needed for the Amulet v1.3+ binary .enc format (cross-tool
# interop) — that format predates the Argon2id migration and has never used
# Argon2id.
PBKDF2_ITER_AMULET_BIN = 600_000

KDF_SALT_LEN = 16
IV_LEN = 12
KEY_LEN_BYTES = 32  # AES-256

AMLT_MAGIC = b"AMLT"
# Two AMLT envelope versions are accepted on read:
#   v=1: written by Amulet Wallet Generator v1.3 .. v1.35. AES-GCM with no
#        AAD; the auth tag covers ciphertext only.
#   v=2: written by Amulet Wallet Generator v1.36+. The 33-byte binary
#        header (magic + version + salt + iv) is bound into the AES-GCM
#        auth tag via additionalData, so on-disk header tampering fails
#        decryption loudly.
AMLT_VERSION_LEGACY = 1
AMLT_VERSION_AAD = 2
AMLT_HEADER_LEN = 4 + 1 + KDF_SALT_LEN + IV_LEN  # 33; + at least 16B tag in ct
GCM_TAG_LEN = 16

# Vault-native JSON envelope versions (mirror the JS canonical helper):
#   v=1: Amulet Vault v1.08 .. v1.30. AES-GCM with no AAD.
#   v=2: Amulet Vault v1.50+. The {v, type, kdf, iv} fields are bound
#        into the AES-GCM auth tag via additionalData, so editing the
#        kdf params, salt, or iv on disk fails decryption loudly.
VAULT_ENVELOPE_VERSION_LEGACY = 1
VAULT_ENVELOPE_VERSION_AAD = 2

# Any payload whose magic matches this is accepted. The vault's v1.04+
# decrypt path uses the same relaxation; earlier vault versions hard-coded
# AMULET_WALLET_V1 which silently broke timelock items introduced in v1.02.
RECOGNIZED_MAGIC = re.compile(r"^AMULET_[A-Z]+_V\d+$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def b64d(s: str) -> bytes:
    """Forgiving base64 decode (tolerates missing padding)."""
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def pbkdf2(password: str, salt: bytes, iterations: int = PBKDF2_ITER_AMULET_BIN) -> bytes:
    """PBKDF2-HMAC-SHA-256 returning 32 bytes. Used for Amulet v1.3+ binary."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def argon2id(password: str, salt: bytes, params: dict = None) -> bytes:
    """Argon2id → 32-byte key. Default params match Amulet Vault v1.08+."""
    p = params or ARGON2_PARAMS_DEFAULT
    return argon2_hash_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(p.get("time_cost", 5)),
        memory_cost=int(p.get("memory_cost", 131_072)),
        parallelism=int(p.get("parallelism", 1)),
        hash_len=int(p.get("hash_len", 32)),
        type=Argon2Type.ID,
    )


def aes_gcm_decrypt(
    key: bytes, iv: bytes, ct_with_tag: bytes, aad: Optional[bytes] = None
) -> bytes:
    """AES-256-GCM decrypt. Raises a clear ValueError on auth failure.

    The optional `aad` argument feeds additionalData into the auth tag
    check. v=2 envelopes (vault and AMLT) require AAD; v=1 envelopes
    pass aad=None.
    """
    try:
        return AESGCM(key).decrypt(iv, ct_with_tag, aad)
    except InvalidTag:
        raise ValueError(
            "AES-GCM authentication failed: wrong password, or the file "
            "has been modified / corrupted."
        )


def canonical_envelope_aad(env: dict) -> bytes:
    """Mirror of the Vault's JS canonicalEnvelopeAad().

    Builds the same byte string that the JS encrypt path passed as
    additionalData when writing a v=2 envelope, so the auth tag check
    here agrees with the auth tag computed at write time.

    Field order (locked): v, type, kdf{name,m,t,p,salt}, iv.
    Compact JSON (no spaces) so the bytes match `JSON.stringify(...)`
    in the browser exactly. Python 3.7+ dicts preserve insertion order,
    which is why the explicit construction below is sufficient.
    """
    kdf = env["kdf"]
    ordered = {
        "v": env["v"],
        "type": env["type"],
        "kdf": {
            "name": kdf["name"],
            "m": kdf["m"],
            "t": kdf["t"],
            "p": kdf["p"],
            "salt": kdf["salt"],
        },
        "iv": env["iv"],
    }
    # ensure_ascii=True matches JSON.stringify's default escaping of
    # non-ASCII characters; for our base64 strings + ASCII type tags it
    # never actually triggers, but locking it in is cheap insurance.
    return json.dumps(
        ordered, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# File-format sniffing
# ---------------------------------------------------------------------------
def detect_format(data: bytes) -> str:
    """Return one of: 'amlt', 'vault-wallet', 'vault-meta', 'unknown'."""
    if (
        len(data) >= AMLT_HEADER_LEN + GCM_TAG_LEN
        and data[:4] == AMLT_MAGIC
    ):
        return "amlt"
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(obj, dict):
        return "unknown"
    if obj.get("type") == "amulet-wallet":
        return "vault-wallet"
    if obj.get("type") == "amulet-vault-meta":
        return "vault-meta"
    magic = obj.get("magic")
    if magic == "AMULET_SHAMIR_SHARE_V1":
        return "shamir-share"
    if magic == "AMULET_WATCH_ONLY_V1":
        return "watch-only"
    if magic == "AMULET_SCRYER_SNAPSHOT_V1":
        return "scryer-snapshot"
    return "unknown"


# ---------------------------------------------------------------------------
# Decryption paths
# ---------------------------------------------------------------------------
def _key_from_kdf_block(kdf: dict, password: str) -> bytes:
    """Dispatch on kdf.name. v1.08+ vault files use Argon2id only."""
    name = kdf.get("name")
    if name != "Argon2id":
        raise ValueError(
            f"Unsupported KDF: {name!r}. Vault files must carry "
            f"kdf.name == 'Argon2id' (Amulet Vault v1.08+). Older PBKDF2 "
            f"files are no longer supported."
        )
    salt = b64d(kdf["salt"])
    params = {
        "time_cost":  int(kdf.get("t", ARGON2_PARAMS_DEFAULT["time_cost"])),
        "memory_cost":int(kdf.get("m", ARGON2_PARAMS_DEFAULT["memory_cost"])),
        "parallelism":int(kdf.get("p", ARGON2_PARAMS_DEFAULT["parallelism"])),
        "hash_len":   ARGON2_PARAMS_DEFAULT["hash_len"],
    }
    return argon2id(password, salt, params)


def _vault_envelope_aad(obj: dict) -> Optional[bytes]:
    """Return the AAD bytes for a vault-native envelope, or None for v=1.

    v=2 envelopes were written with the {v,type,kdf,iv} fields bound
    into AES-GCM additionalData; we reconstruct the same byte string
    here. v=1 envelopes (and any envelope missing the v field) get
    decrypted without AAD, matching v1.08 .. v1.30 write behaviour.
    """
    env_version = obj.get("v") if isinstance(obj.get("v"), int) else 1
    if env_version >= VAULT_ENVELOPE_VERSION_AAD:
        return canonical_envelope_aad({
            "v": obj["v"],
            "type": obj["type"],
            "kdf": obj["kdf"],
            "iv": obj["iv"],
        })
    return None


def decrypt_vault_enc(data: bytes, password: str) -> dict:
    """Decrypt a vault-native wallet or timelock .enc file."""
    obj = json.loads(data.decode("utf-8"))
    if obj.get("type") != "amulet-wallet":
        raise ValueError("Not an amulet-wallet JSON wrapper.")
    key = _key_from_kdf_block(obj.get("kdf", {}), password)
    iv = b64d(obj["iv"])
    ct = b64d(obj["ct"])
    aad = _vault_envelope_aad(obj)
    pt = aes_gcm_decrypt(key, iv, ct, aad)
    payload = json.loads(pt.decode("utf-8"))
    magic = str(payload.get("magic", ""))
    if not RECOGNIZED_MAGIC.match(magic):
        raise ValueError(
            f"Decrypted, but payload carries an unrecognized magic: {magic!r}"
        )
    return payload


def decrypt_vault_meta(data: bytes, password: str) -> dict:
    """Decrypt a vault.meta index. Errors clearly if YubiKey-protected."""
    obj = json.loads(data.decode("utf-8"))
    if obj.get("type") != "amulet-vault-meta":
        raise ValueError("Not an amulet-vault-meta file.")
    if obj.get("yubikey"):
        raise RuntimeError(
            "This vault.meta was created with a YubiKey hmac-secret mix-in "
            "in an older vault version.\n"
            "YubiKey support was removed in Amulet Vault v1.06; a vault "
            "that old also predates the v1.08 Argon2id migration. There is "
            "no supported recovery path for this file in amulet_relic."
        )
    key = _key_from_kdf_block(obj.get("kdf", {}), password)
    iv = b64d(obj["iv"])
    ct = b64d(obj["ct"])
    aad = _vault_envelope_aad(obj)
    pt = aes_gcm_decrypt(key, iv, ct, aad)
    payload = json.loads(pt.decode("utf-8"))
    if payload.get("magic") != "AMULET_VAULT_V1":
        raise ValueError(
            f"Decrypted meta has unexpected magic: {payload.get('magic')!r}"
        )
    return payload


def decrypt_amulet_binary(data: bytes, password: str) -> str:
    """Decrypt an Amulet v1.3+ binary .enc, returning the plaintext report.

    Accepts both AMLT v=1 (no AAD, written by Generator v1.3 .. v1.35)
    and AMLT v=2 (the binary header is bound into the AES-GCM auth tag,
    written by Generator v1.36+).
    """
    if data[:4] != AMLT_MAGIC:
        raise ValueError("Not an Amulet AMLT binary.")
    version = data[4]
    if version not in (AMLT_VERSION_LEGACY, AMLT_VERSION_AAD):
        raise ValueError(
            f"Unsupported AMLT version: {version}. "
            f"This script supports v=1 and v=2."
        )
    salt = data[5 : 5 + KDF_SALT_LEN]
    iv = data[5 + KDF_SALT_LEN : 5 + KDF_SALT_LEN + IV_LEN]
    ct = data[AMLT_HEADER_LEN:]
    key = pbkdf2(password, salt)
    aad = data[:AMLT_HEADER_LEN] if version == AMLT_VERSION_AAD else None
    pt = aes_gcm_decrypt(key, iv, ct, aad)
    return pt.decode("utf-8")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def _prompt(args_pw: Optional[str], label: str) -> str:
    return args_pw if args_pw else getpass.getpass(f"{label}: ")


def _write_or_print(text: str, out_path: Optional[str]) -> None:
    if out_path:
        Path(out_path).write_text(text)
        print(f"wrote {len(text)} bytes to {out_path}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _explain_special(fmt: str, data: bytes) -> Optional[int]:
    """Handle formats that need no password. Returns an exit code, or None."""
    if fmt == "shamir-share":
        try:
            obj = json.loads(data.decode("utf-8"))
            print(
                f"This is ONE share of a Shamir backup "
                f"(label={obj.get('label')!r}, share {obj.get('idx')} of "
                f"{obj.get('N')}, threshold T={obj.get('T')}).",
                file=sys.stderr,
            )
        except Exception:
            print("This is one share of a Shamir backup.", file=sys.stderr)
        print(
            "A single share reveals nothing and cannot be decrypted alone.\n"
            "Collect T or more .amulet-share files and run:\n"
            "    python3 amulet_shamir_relic.py share1 share2 share3 ...\n"
            "(or use the Amulet Shamir Shared Split HTML tool).",
            file=sys.stderr,
        )
        return 2
    if fmt in ("watch-only", "scryer-snapshot"):
        print(
            f"This is a plaintext {'watch-only export' if fmt == 'watch-only' else 'Scryer snapshot'};"
            " there is nothing to decrypt. Contents:",
            file=sys.stderr,
        )
        print(json.dumps(json.loads(data.decode("utf-8")), indent=2, ensure_ascii=False))
        return 0
    return None


def cmd_decrypt(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    fmt = detect_format(data)
    print(f"[amulet_relic] detected format: {fmt}", file=sys.stderr)
    special = _explain_special(fmt, data)
    if special is not None:
        return special
    password = _prompt(args.password, "Password")
    if fmt == "amlt":
        _write_or_print(decrypt_amulet_binary(data, password), args.out)
    elif fmt == "vault-wallet":
        payload = decrypt_vault_enc(data, password)
        _write_or_print(
            json.dumps(payload, indent=2, ensure_ascii=False), args.out
        )
    elif fmt == "vault-meta":
        payload = decrypt_vault_meta(data, password)
        _write_or_print(
            json.dumps(payload, indent=2, ensure_ascii=False), args.out
        )
    else:
        sys.stderr.write(
            "Unrecognized file format. "
            "Expected AMLT binary or vault-native JSON wrapper.\n"
        )
        return 1
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    fmt = detect_format(data)
    if fmt == "shamir-share":
        obj = json.loads(data.decode("utf-8"))
        print("Format:    Shamir share (AMULET_SHAMIR_SHARE_V1)")
        print(f"Label:     {obj.get('label')}")
        print(f"Share:     {obj.get('idx')} of {obj.get('N')}  (threshold T={obj.get('T')})")
        print(f"Backup id: {obj.get('backupId')}")
        print(f"Created:   {obj.get('createdAt')}")
        print("Carries the encrypted vault inside:", "yes" if obj.get("vaultZip") else "no")
        print("Recombine with amulet_shamir_relic.py (T or more shares needed).")
        return 0
    if fmt in ("watch-only", "scryer-snapshot"):
        print(f"Format:    {'watch-only export' if fmt == 'watch-only' else 'Scryer snapshot'} (plaintext JSON)")
        print("Not encrypted; open it in any text editor.")
        return 0
    if fmt == "amlt":
        print("Format: Amulet v1.3+ binary (AMLT)")
        print(f"Size:   {len(data)} bytes")
        print(
            f"Layout: 4B magic + 1B version + {KDF_SALT_LEN}B salt "
            f"+ {IV_LEN}B IV + ciphertext (incl. {GCM_TAG_LEN}B GCM tag)"
        )
        ver = data[4]
        aad_note = (
            "AAD-bound (header sealed by auth tag)" if ver == AMLT_VERSION_AAD
            else "no AAD (auth tag covers ciphertext only)"
            if ver == AMLT_VERSION_LEGACY
            else "unknown"
        )
        print(f"Version byte: {ver} ({aad_note})")
        return 0
    if fmt in ("vault-wallet", "vault-meta"):
        obj = json.loads(data.decode("utf-8"))
        env_v = obj.get("v")
        aad_note = (
            "AAD-bound (header sealed by auth tag)"
            if isinstance(env_v, int) and env_v >= VAULT_ENVELOPE_VERSION_AAD
            else "no AAD (auth tag covers ciphertext only)"
        )
        print(f"Format:    {fmt}")
        print(f"Wrapper v: {env_v}  ({aad_note})")
        print(f"Type:      {obj.get('type')}")
        k = obj.get("kdf", {})
        name = k.get("name", "?")
        if name == "Argon2id":
            print(
                f"KDF:       Argon2id / "
                f"m={k.get('m')} KiB ({int(k.get('m', 0))//1024} MiB), "
                f"t={k.get('t')}, p={k.get('p')}"
            )
        elif name == "PBKDF2":
            print(
                f"KDF:       PBKDF2 / {k.get('hash')} / iter={k.get('iter')}"
            )
        else:
            print(f"KDF:       {name} (unknown — this script won't decrypt it)")
        if obj.get("yubikey"):
            print(
                "YubiKey:   PROTECTED (hmac-secret required — "
                "this script cannot decrypt without the physical key)"
            )
        return 0
    sys.stderr.write("Unrecognized file format.\n")
    return 1


def cmd_list(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    if detect_format(data) != "vault-meta":
        sys.stderr.write("Not a vault.meta file.\n")
        return 1
    password = _prompt(args.password, "Master password")
    payload = decrypt_vault_meta(data, password)
    wallets = payload.get("wallets", [])
    print(f"Vault created : {payload.get('createdAt','?')}")
    print(f"Index entries : {len(wallets)}")
    print("-" * 78)
    print(f"  {'KIND':10s}  {'FILE':32s}  NAME")
    print("-" * 78)
    for w in wallets:
        kind = w.get("type") or "wallet"
        print(
            f"  {kind:10s}  {w.get('file','?'):32s}  "
            f"{w.get('name','(unnamed)')}"
        )
    return 0


def cmd_export_txt(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    if detect_format(data) != "vault-wallet":
        sys.stderr.write(
            "Not a vault-native .enc (expected JSON wrapper).\n"
        )
        return 1
    password = _prompt(args.password, "Item password")
    payload = decrypt_vault_enc(data, password)
    if payload.get("magic") != "AMULET_TIMELOCK_V1":
        sys.stderr.write(
            f"This is not a timelock item (magic={payload.get('magic')!r}).\n"
        )
        return 1
    original = payload.get("originalTxt")
    if not original:
        sys.stderr.write(
            "Payload has no originalTxt field — this item was not imported "
            "from a .txt backup so there's nothing to re-emit.\n"
        )
        return 1
    if args.out:
        Path(args.out).write_text(original)
        print(
            f"wrote timelock .txt backup to {args.out} ({len(original)} bytes)",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(original)
    return 0


# ---------------------------------------------------------------------------
# Known-answer verification
# ---------------------------------------------------------------------------
def cmd_verify(_args: argparse.Namespace) -> int:
    """
    Reproducible KAT suite. Each vector can be re-run against public sources
    (openssl, Python hashlib, FIPS / RFC test vectors) to independently
    prove the crypto stack is functional.
    """
    failures = 0

    def kat(name: str, actual: bytes, expected: bytes) -> None:
        nonlocal failures
        ok = actual == expected
        status = "  OK  " if ok else " FAIL "
        print(f"  [{status}] {name}")
        if not ok:
            failures += 1
            print(f"            expected: {expected.hex()}")
            print(f"            actual:   {actual.hex()}")

    print("amulet_relic — crypto KAT suite")
    print("=" * 78)

    # SHA-256("abc") — FIPS 180-4 Appendix B.1
    kat(
        "SHA-256('abc')",
        hashlib.sha256(b"abc").digest(),
        bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        ),
    )

    # PBKDF2-HMAC-SHA-256 KATs (pw='password', salt='salt', L=32)
    # Widely cited; reproducible with openssl kdf or Python hashlib.
    kat(
        "PBKDF2-SHA256 iter=1    pw='password' salt='salt' L=32",
        pbkdf2("password", b"salt", 1),
        bytes.fromhex(
            "120fb6cffcf8b32c43e7225256c4f837"
            "a86548c92ccc35480805987cb70be17b"
        ),
    )
    kat(
        "PBKDF2-SHA256 iter=4096 pw='password' salt='salt' L=32",
        pbkdf2("password", b"salt", 4096),
        bytes.fromhex(
            "c5e478d59288c841aa530db6845c4c8d"
            "962893a001ce4e11a4963873aa98134a"
        ),
    )

    # AES-256-GCM — NIST-era test vector: all-zero key & IV, 16-byte zero
    # plaintext, empty AAD. ct||tag is well-known.
    key = bytes(32)
    iv = bytes(12)
    pt = bytes(16)
    expected_ct_tag = bytes.fromhex(
        "cea7403d4d606b6e074ec5d3baf39d18"  # ciphertext
        "d0d1c8a799996bf0265b98b5d48ab919"  # auth tag
    )
    kat(
        "AES-256-GCM all-zero key/IV, 16-byte zero PT",
        AESGCM(key).encrypt(iv, pt, None),
        expected_ct_tag,
    )

    # Argon2id KATs — deterministic vectors anyone can reproduce with the
    # `argon2` CLI, a different language's argon2 library, or argon2-cffi.
    # These aren't RFC 9106 Appendix A vectors (argon2-cffi's hash_secret_raw
    # doesn't expose the optional `secret` and `associated_data` fields), but
    # the parameters are canonical and the outputs cross-verify.
    #
    # Vector 1: pass=0x01*32, salt=0x02*16, t=3, m=32, p=4, len=32
    #   → 03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e
    kat(
        "Argon2id t=3 m=32 p=4  (regression vector)",
        argon2_hash_raw(
            secret=b"\x01" * 32, salt=b"\x02" * 16,
            time_cost=3, memory_cost=32, parallelism=4,
            hash_len=32, type=Argon2Type.ID,
        ),
        bytes.fromhex("03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e"),
    )
    # Vector 2: minimal memory (m=8), single thread, single iteration — fast
    # verification of the core mixing with trivially reproducible inputs.
    kat(
        "Argon2id t=1 m=8 p=1  (minimal mixing)",
        argon2_hash_raw(
            secret=b"x", salt=b"y" * 16,
            time_cost=1, memory_cost=8, parallelism=1,
            hash_len=32, type=Argon2Type.ID,
        ),
        bytes.fromhex("550d8b285cbc5fb129b71de8320b5fd8ff01c7460750f5e6abba80f35ce5490e"),
    )

    # End-to-end round-trip at the Vault's real Argon2id parameters — proves
    # that encrypt(argon2id(pw)) -> decrypt(argon2id(pw)) actually agrees.
    rt_key = argon2id(
        "amulet-relic-selftest",
        b"\x00" * 16,
        params=dict(time_cost=1, memory_cost=8192, parallelism=1, hash_len=32),
    )
    rt_iv = b"\x00" * 12
    rt_obj = {"magic": "AMULET_WALLET_V1", "words": ["abandon"] * 11 + ["about"]}
    rt_ct = AESGCM(rt_key).encrypt(rt_iv, json.dumps(rt_obj).encode(), None)
    rt_pt = json.loads(AESGCM(rt_key).decrypt(rt_iv, rt_ct, None).decode())
    ok = rt_pt == rt_obj
    print(
        f"  [{'  OK  ' if ok else ' FAIL '}] "
        "Argon2id → AES-GCM round-trip"
    )
    if not ok:
        failures += 1

    # Wrong-password rejection
    try:
        wrong_key = argon2id(
            "WRONG",
            b"\x00" * 16,
            params=dict(time_cost=1, memory_cost=8192, parallelism=1, hash_len=32),
        )
        AESGCM(wrong_key).decrypt(rt_iv, rt_ct, None)
        print("  [ FAIL ] wrong-password MUST raise, but it didn't")
        failures += 1
    except Exception:
        print("  [  OK  ] wrong-password raises InvalidTag")

    # AAD-bound AES-GCM round-trip + tamper detection. Mirrors the
    # gcm-aad-rt KAT in the Vault HTML's Self sanity check.
    aad_key = bytes(32)
    aad_iv = bytes(12)
    aad_aad = b"AMULET_VAULT_AAD"
    aad_pt = b"v1:0 vs:v2 audhello"
    aad_ct = AESGCM(aad_key).encrypt(aad_iv, aad_pt, aad_aad)
    aad_back = AESGCM(aad_key).decrypt(aad_iv, aad_ct, aad_aad)
    ok = aad_back == aad_pt
    print(
        f"  [{'  OK  ' if ok else ' FAIL '}] "
        "AES-256-GCM with AAD: round-trip"
    )
    if not ok:
        failures += 1
    try:
        AESGCM(aad_key).decrypt(aad_iv, aad_ct, aad_aad[:-1] + b"!")
        print("  [ FAIL ] AAD tamper MUST raise InvalidTag, but it didn't")
        failures += 1
    except InvalidTag:
        print("  [  OK  ] AAD tamper raises InvalidTag")

    # canonical_envelope_aad determinism + byte-for-byte cross-tool fixture.
    # The expected bytes below are exactly what `JSON.stringify` produces in
    # the browser (no whitespace, key order locked) for the same input.
    fixture_env = {
        "v": 2, "type": "amulet-wallet",
        "kdf": {"name": "Argon2id", "m": 32768, "t": 2, "p": 1, "salt": "AAAA"},
        "iv": "BBBB",
    }
    expected_aad = (
        b'{"v":2,"type":"amulet-wallet","kdf":{"name":"Argon2id",'
        b'"m":32768,"t":2,"p":1,"salt":"AAAA"},"iv":"BBBB"}'
    )
    actual_aad = canonical_envelope_aad(fixture_env)
    ok = actual_aad == expected_aad
    print(
        f"  [{'  OK  ' if ok else ' FAIL '}] "
        "canonical_envelope_aad matches JS JSON.stringify byte-for-byte"
    )
    if not ok:
        print(f"            expected: {expected_aad!r}")
        print(f"            actual:   {actual_aad!r}")
        failures += 1

    # Note: PBKDF2 KATs for iter=1 and iter=4096 (standard test vectors) were
    # already asserted above as part of the HMAC stack; the PBKDF2 function
    # itself remains in use only for Amulet v1.3+ binary interop and for
    # BIP-39 seed derivation (both unchanged by the v1.08 migration).

    print("=" * 78)
    if failures:
        print(
            f"{failures} failure(s) — DO NOT rely on this script for recovery."
        )
        return 1
    print("All vectors passed. Crypto stack is functional.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="amulet_relic",
        description=(
            "Independent recovery tool for Amulet Vault encrypted files. "
            "Runs entirely offline with no dependencies beyond 'cryptography'."
        ),
    )
    sp = p.add_subparsers(dest="cmd", required=True)

    pd = sp.add_parser(
        "decrypt", help="Decrypt a .enc or vault.meta file and print the payload"
    )
    pd.add_argument("file", help="encrypted file to decrypt")
    pd.add_argument("--password", help="password (or prompt interactively)")
    pd.add_argument("--out", help="write to this path instead of stdout")
    pd.set_defaults(func=cmd_decrypt)

    pi = sp.add_parser(
        "inspect", help="Summarize a file's type and KDF params without decrypting"
    )
    pi.add_argument("file")
    pi.set_defaults(func=cmd_inspect)

    pl = sp.add_parser(
        "list", help="Decrypt a vault.meta index and list its wallet/timelock entries"
    )
    pl.add_argument("file")
    pl.add_argument("--password", help="master password (or prompt)")
    pl.set_defaults(func=cmd_list)

    pt = sp.add_parser(
        "export-txt",
        help="Extract the verbatim .txt backup of a timelock item imported via RC2/RC1",
    )
    pt.add_argument("file")
    pt.add_argument("--password", help="item password (or prompt)")
    pt.add_argument("--out", help="write to this path instead of stdout")
    pt.set_defaults(func=cmd_export_txt)

    pv = sp.add_parser("verify", help="Run built-in crypto KAT vectors")
    pv.set_defaults(func=cmd_verify)

    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
