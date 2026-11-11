"""Generate public migration fixtures with Python's standard library and qrrs."""

import base64
from pathlib import Path
import shutil
import subprocess
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def integer(tag, value):
    return varint(tag << 3) + varint(value)


def blob(tag, value):
    return varint((tag << 3) | 2) + varint(len(value)) + value


def account(name, secret, algorithm=1, digits=1, kind=2):
    return b"".join([
        blob(1, secret),
        blob(2, name.encode()),
        blob(3, b"Example"),
        integer(4, algorithm),
        integer(5, digits),
        integer(6, kind),
    ])


def payload(accounts, batch_size=1, version=1):
    return b"".join(blob(1, item) for item in accounts) + b"".join([
        integer(2, version),
        integer(3, batch_size),
        integer(4, 0),
        integer(5, 42),
    ])


def main():
    qrrs = shutil.which("qrrs") or str(Path.home() / ".cargo/bin/qrrs")
    # Public RFC 6238 Appendix B seeds. Never use these for real accounts.
    alice = account("Example:alice", b"12345678901234567890")
    bob = account("Example:bob", b"12345678901234567890123456789012", algorithm=2, digits=2)
    hotp = account("Example:counter", b"12345678901234567890", kind=1)
    cases = {
        "migration-single": payload([alice]),
        "migration-v2": payload([alice], version=2),
        "migration-multiple": payload([alice, bob]),
        "migration-hotp": payload([hotp]),
        "migration-batch": payload([alice], batch_size=2),
    }
    for name, data in cases.items():
        uri = "otpauth-migration://offline?data=" + quote(base64.b64encode(data).decode(), safe="")
        ROOT.joinpath(name + ".txt").write_text(uri + "\n")
        subprocess.run([qrrs, uri, str(ROOT / (name + ".png"))], check=True)
        decoded = subprocess.check_output([qrrs, "--read", str(ROOT / (name + ".png"))], text=True)
        assert decoded.strip() == uri, "fixture QR roundtrip mismatch"
    print(f"Verified {len(cases)} public migration QR fixtures")


if __name__ == "__main__":
    main()
