"""Authenticated, encrypted snapshots of Tailscale node and SSH identities."""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path


SNAPSHOT_PATH = Path(__file__).with_name("tailscale-state.enc")
KEY_ENV = "TAILSCALE_STATE_KEY"
MAGIC = b"AGSB-TAILSCALE-STATE\x00\x01"
MAX_SIZE = 4 * 1024 * 1024


def _aesgcm(key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("Tailscale: install cryptography with pip install -r requirements.txt") from exc
    try:
        raw = base64.b64decode(key.strip() + "=" * (-len(key.strip()) % 4), altchars=b"-_", validate=True)
        if len(raw) != 32:
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Tailscale: {KEY_ENV} must be a base64url-encoded 32-byte key") from exc
    return AESGCM(raw)


def _identity_name(name):
    # The state store includes machine keys, node keys and login profiles.
    # SSH host keys are separate files. Caches, logs and Taildrop are excluded.
    return name == "tailscaled.state" or bool(re.fullmatch(r"ssh_host_[a-zA-Z0-9_.-]+", name))


def _validate(document):
    try:
        if document["version"] != 1 or not re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", document["hostname"]
        ):
            raise ValueError
        files = document["files"]
        if not isinstance(files, dict) or "tailscaled.state" not in files or len(files) > 32:
            raise ValueError
        decoded = {}
        for name, value in files.items():
            if not _identity_name(name):
                raise ValueError
            decoded[name] = base64.b64decode(value, validate=True)
        if sum(map(len, decoded.values())) > MAX_SIZE:
            raise ValueError
        state = json.loads(decoded["tailscaled.state"])
        if not isinstance(state.get("_machinekey"), str) or not state["_machinekey"]:
            raise ValueError
        return decoded
    except (KeyError, ValueError, TypeError, AttributeError):
        # Parsing errors can contain private key material; keep the error generic.
        raise ValueError("Tailscale: invalid identity snapshot") from None


def collect_state(state_dir, hostname):
    """Read only node identity files, checking for a concurrent state update."""
    state_dir = Path(state_dir)
    for _ in range(3):
        files = {}
        for path in sorted(state_dir.iterdir()):
            if not _identity_name(path.name):
                continue
            if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > MAX_SIZE:
                raise ValueError("Tailscale: identity files must be regular files smaller than 4 MiB")
            files[path.name] = base64.b64encode(path.read_bytes()).decode("ascii")
        document = {"version": 1, "hostname": hostname.lower(), "files": files}
        decoded = _validate(document)
        if decoded["tailscaled.state"] == (state_dir / "tailscaled.state").read_bytes():
            return document
    raise RuntimeError("Tailscale: identity changed during export; retry the export")


def encrypt(document, key):
    _validate(document)
    plaintext = json.dumps(document, separators=(",", ":")).encode()
    if len(plaintext) > MAX_SIZE:
        raise ValueError("Tailscale: snapshot is too large")
    nonce = secrets.token_bytes(12)
    return MAGIC + nonce + _aesgcm(key).encrypt(nonce, plaintext, MAGIC)


def decrypt(blob, key):
    cipher = _aesgcm(key)
    if not blob.startswith(MAGIC) or not len(MAGIC) + 28 <= len(blob) <= MAX_SIZE + 128:
        raise ValueError("Tailscale: unsupported or damaged encrypted snapshot")
    offset = len(MAGIC)
    try:
        document = json.loads(cipher.decrypt(blob[offset:offset + 12], blob[offset + 12:], MAGIC))
    except Exception:
        raise ValueError(f"Tailscale: snapshot authentication failed; check {KEY_ENV} and the encrypted file") from None
    _validate(document)
    return document


def load_snapshot(environ=None):
    env = os.environ if environ is None else environ
    key = env.get(KEY_ENV, "").strip()
    if not key:
        raise ValueError(f"Tailscale: {KEY_ENV} is required for the bundled identity snapshot")
    try:
        if SNAPSHOT_PATH.stat().st_size > MAX_SIZE + 128:
            raise ValueError("Tailscale: encrypted snapshot is too large")
        blob = SNAPSHOT_PATH.read_bytes()
    except OSError as exc:
        raise ValueError("Tailscale: bundled tailscale-state.enc cannot be read") from exc
    document = decrypt(blob, key)
    return document, hashlib.sha256(blob).hexdigest()


def _write_private(path, data):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".agsb-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore_state(state_dir, environ=None):
    """Restore an empty node; preserve newer local state for the same identity."""
    document, _ = load_snapshot(environ)
    files = _validate(document)
    state_dir = Path(state_dir)
    if state_dir.is_symlink():
        raise ValueError("Tailscale: state directory must not be a symlink")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    for name in files:
        path = state_dir / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError("Tailscale: unsafe identity file in state directory")
    identity = state_dir / "tailscaled.state"
    if identity.exists():
        try:
            current = json.loads(identity.read_bytes())["_machinekey"]
            saved = json.loads(files["tailscaled.state"])["_machinekey"]
        except (KeyError, ValueError, TypeError):
            raise ValueError("Tailscale: existing local identity is invalid") from None
        if current != saved:
            raise ValueError("Tailscale: local identity differs from the snapshot; stop the service and select the matching state directory")
        for name in files:
            path = state_dir / name
            if path.exists():
                path.chmod(0o600)
            else:
                _write_private(path, files[name])
        return False
    # Write the state file last so an interrupted restore can be retried.
    for name in sorted(files, key=lambda item: item == "tailscaled.state"):
        _write_private(state_dir / name, files[name])
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen", help="print a new random encryption key")
    export = sub.add_parser("export", help="encrypt local node identity files")
    export.add_argument("--state-dir", type=Path, default=Path.home() / ".agsb" / "tailscale")
    export.add_argument("--hostname", default="streamlit-agsb")
    export.add_argument("--output", type=Path, default=SNAPSHOT_PATH)
    args = parser.parse_args()
    if args.command == "keygen":
        print(secrets.token_urlsafe(32))
        return
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        parser.error(f"set {KEY_ENV} before exporting")
    _write_private(args.output, encrypt(collect_state(args.state_dir, args.hostname), key))
    print(f"Tailscale: encrypted identity saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as exc:
        raise SystemExit(str(exc)) from None
