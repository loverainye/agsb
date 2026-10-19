"""Shared settings, credential handling and app logs for ArgoSB services."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import tailscale_state


CLOUDFLARE_TAG = "cloudflare-tunnel"
_RELAYS = {}
_RELAY_LOCK = threading.Lock()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def cloudflare_settings(token):
    token = token.strip()
    if not token:
        raise ValueError("AGK is required for the embedded Cloudflare Tunnel")
    return {"token_hash": hashlib.sha256(token.encode()).hexdigest()}


def _add_local_resolver(config):
    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    if not any(server.get("tag") == "local-dns" for server in servers):
        servers.append({"type": "local", "tag": "local-dns"})
    dns.setdefault("final", "local-dns")
    route = config.setdefault("route", {})
    route.setdefault("default_domain_resolver", "local-dns")
    route.setdefault("final", "direct")


def add_cloudflare(config):
    # The remote tunnel config still selects DOMAIN -> http://localhost:PORT.
    # Empty protocol/edge options use automatic protocol and address selection.
    config.setdefault("inbounds", []).append({"type": "cloudflared", "tag": CLOUDFLARE_TAG})
    _add_local_resolver(config)
    config["route"].setdefault("rules", []).append({
        "inbound": [CLOUDFLARE_TAG], "action": "route", "outbound": "direct",
    })


def settings_from_env(uuid_value, environ=None):
    env = os.environ if environ is None else environ
    key = env.get("TAILSCALE_AUTH_KEY", "").strip()
    state_key = env.get(tailscale_state.KEY_ENV, "").strip()
    if not key and not state_key:
        return None
    snapshot = None
    snapshot_hash = None
    if state_key or tailscale_state.SNAPSHOT_PATH.exists():
        snapshot, snapshot_hash = tailscale_state.load_snapshot(env)
    default_hostname = snapshot["hostname"] if snapshot else f"agsb-{uuid_value[:8]}"
    hostname = env.get("TAILSCALE_HOSTNAME", "").strip() or default_hostname
    if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", hostname):
        raise ValueError("TAILSCALE_HOSTNAME must be a hostname of 1-63 letters, numbers or hyphens")
    ephemeral = env.get("TAILSCALE_EPHEMERAL", "false" if snapshot else "true").strip().lower()
    if ephemeral not in ("true", "false", "1", "0"):
        raise ValueError("TAILSCALE_EPHEMERAL must be true or false")
    if snapshot and ephemeral in ("true", "1"):
        raise ValueError("Tailscale: encrypted identity restore requires TAILSCALE_EPHEMERAL=false")
    tags = sorted(set(value.strip() for value in env.get("TAILSCALE_ADVERTISE_TAGS", "").split(",") if value.strip()))
    if any(not re.fullmatch(r"tag:[a-zA-Z][a-zA-Z0-9-]*", tag) for tag in tags):
        raise ValueError("TAILSCALE_ADVERTISE_TAGS must contain comma-separated tag:name values")
    # The implementation marker migrates embedded endpoints on the next run.
    settings = {
        "hostname": hostname.lower(),
        "ephemeral": ephemeral in ("true", "1"),
        "auth_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        "implementation": "official-tailscaled-userspace-bin-v2",
        "advertise_connector": True,
        "advertise_exit_node": True,
        "advertise_tags": tags,
    }
    if snapshot_hash:
        settings["state_snapshot"] = snapshot_hash
    return settings


def runtime_config(config, environ=None):
    """Copy the template and inject credentials only into the runtime JSON."""
    env = os.environ if environ is None else environ
    result = json.loads(json.dumps(config))
    for inbound in result.get("inbounds", []):
        if inbound.get("tag") == CLOUDFLARE_TAG:
            token = (env.get("AGK", "").strip() or env.get("agk", "").strip())
            if not token:
                raise ValueError("AGK is required to start the configured Cloudflare Tunnel")
            inbound["token"] = token
    if any(endpoint.get("type") == "tailscale" for endpoint in result.get("endpoints", [])):
        raise ValueError("Tailscale: legacy embedded endpoint must be regenerated for standalone tailscaled")
    return json.dumps(result)


def redact(message, secrets=()):
    message = _ANSI.sub("", str(message))
    for secret in secrets:
        secret = secret.strip()
        if secret:
            message = message.replace(secret, "[redacted]")
    for name in ("TAILSCALE_AUTH_KEY", tailscale_state.KEY_ENV, "AGK", "agk"):
        secret = os.environ.get(name, "").strip()
        if secret:
            message = message.replace(secret, "[redacted]")
    return re.sub(r"tskey-[A-Za-z0-9_-]+", "[redacted]", message)


def singbox_environment():
    environment = os.environ.copy()
    # sing-box's CLI uses SUDO_* to select a file owner. Streamlit can inherit
    # these from its bootstrap while running as a different, unprivileged user.
    for name in ("AGK", "agk", "TAILSCALE_AUTH_KEY", tailscale_state.KEY_ENV, "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
        environment.pop(name, None)
    return environment


def validate_config(binary, config):
    features = []
    if any(item.get("tag") == CLOUDFLARE_TAG for item in config.get("inbounds", [])):
        features.append(("Cloudflare", "with_cloudflared"))
    child_env = singbox_environment()
    version = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=15, env=child_env)
    match = re.search(r"sing-box version (\d+)\.(\d+)\.(\d+)([^\s]*)", version.stdout)
    if version.returncode or not match or tuple(map(int, match.group(1, 2, 3))) < (1, 14, 0):
        raise RuntimeError("Cloudflare Tunnel requires sing-box >= 1.14.0")
    tags = set(re.findall(r"with_[a-z0-9_]+", version.stdout))
    for feature, tag in features:
        if tag not in tags:
            raise RuntimeError(f"sing-box was built without {tag}; {feature} is unavailable")
    checked = subprocess.run(
        [str(binary), "check", "-c", "stdin"], input=runtime_config(config),
        capture_output=True, text=True, timeout=20, env=child_env,
    )
    if checked.returncode:
        raise RuntimeError("sing-box configuration check failed: " + redact(checked.stderr or checked.stdout))
    for feature, _ in features:
        print(f"{feature}: sing-box {match.group(0).split()[-1]} configuration check passed", flush=True)


def run_singbox(install_dir):
    """Replace this short-lived launcher with sing-box, retaining its PID."""
    install_dir = Path(install_dir).resolve()
    config = json.loads((install_dir / "sb.json").read_text())
    payload = runtime_config(config).encode()
    if any(item.get("tag") == CLOUDFLARE_TAG for item in config.get("inbounds", [])):
        print("Cloudflare: starting Tunnel in the existing sing-box process; token injected from AGK", flush=True)
        print("Cloudflare: connection and ingress diagnostics are in sb.log; startup does not yet confirm edge registration", flush=True)
    child_env = singbox_environment()
    if any(name in os.environ for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID")):
        print("sing-box: inherited sudo ownership metadata removed; files belong to the current app user", flush=True)
    # An anonymous file avoids both a persistent credential file and pipe limits.
    if hasattr(os, "memfd_create"):
        stream = os.fdopen(os.memfd_create("sing-box-config", os.MFD_CLOEXEC), "w+b")
    else:
        stream = tempfile.TemporaryFile()
    with stream:
        stream.write(payload)
        stream.seek(0)
        os.dup2(stream.fileno(), 0, inheritable=True)
        binary = str(install_dir / "sing-box")
        os.execve(binary, [binary, "run", "-c", "stdin"], child_env)


class _LogRelay:
    def __init__(self, state_dir, installer_log, secrets=()):
        self.state_dir = state_dir
        self.secrets = tuple(secrets)
        self.paths = (installer_log, state_dir / "sb.log", state_dir / "tailscale.log")
        self.positions = {}
        self.pending = {}
        self.sb_pid = self._pid()
        self.tailscale_pid = self._pid("tailscale-launcher.pid")
        for path in self.paths:
            try:
                stat = path.stat()
                self.positions[path] = (stat.st_ino, stat.st_size)
            except OSError:
                pass
        self.stop = threading.Event()

    def _pid(self, filename="sbpid.log"):
        try:
            return (self.state_dir / filename).read_text().strip()
        except OSError:
            return None

    def poll(self):
        pid = self._pid()
        if pid != self.sb_pid:
            self.positions.pop(self.state_dir / "sb.log", None)
            self.pending.pop(self.state_dir / "sb.log", None)
            self.sb_pid = pid
        tailscale_pid = self._pid("tailscale-launcher.pid")
        if tailscale_pid != self.tailscale_pid:
            self.positions.pop(self.state_dir / "tailscale.log", None)
            self.pending.pop(self.state_dir / "tailscale.log", None)
            self.tailscale_pid = tailscale_pid
        for path in self.paths:
            try:
                with path.open("rb") as stream:
                    stat = os.fstat(stream.fileno())
                    inode, offset = self.positions.get(path, (stat.st_ino, 0))
                    if inode != stat.st_ino or stat.st_size < offset:
                        offset = 0
                        self.pending.pop(path, None)
                    stream.seek(offset)
                    content = self.pending.get(path, b"") + stream.read()
                    self.positions[path] = (stat.st_ino, stream.tell())
                lines = content.split(b"\n")
                self.pending[path] = lines.pop()
                for line in lines:
                    message = redact(line.decode("utf-8", errors="replace"), self.secrets)
                    if (path.name == "tailscale.log" or "Tailscale" in message or "endpoint/tailscale[" in message
                            or "Cloudflare:" in message or "inbound/cloudflared[" in message
                            or "FATAL" in message or "Traceback" in message
                            or "Error:" in message or "失败" in message or "错误" in message):
                        # Routine network dial messages would overwhelm app logs.
                        if not any(text in message for text in (
                            "output connection to", "output packet connection",
                            "inbound connection to", "inbound packet connection to",
                        )):
                            print(("Tailscale: " if path.name == "tailscale.log" and "Tailscale" not in message else "") + message, flush=True)
            except OSError:
                continue

    def run(self):
        while not self.stop.wait(0.5):
            self.poll()


def start_log_relay(state_dir, installer_log, secrets=()):
    """One daemon thread per app, reused across Streamlit reruns."""
    state_dir, installer_log = Path(state_dir), Path(installer_log)
    with _RELAY_LOCK:
        key = str(state_dir.resolve())
        relay = _RELAYS.get(key)
        if relay is None:
            relay = _LogRelay(state_dir, installer_log, secrets=secrets)
            threading.Thread(target=relay.run, name="singbox-log-relay", daemon=True).start()
            _RELAYS[key] = relay
        else:
            relay.secrets = tuple(dict.fromkeys((*relay.secrets, *secrets)))
        if relay.paths[0] != installer_log:
            # UUID changes select a new installer log in the same app directory.
            try:
                stat = installer_log.stat()
                relay.positions[installer_log] = (stat.st_ino, stat.st_size)
            except OSError:
                relay.positions.pop(installer_log, None)
            relay.pending.pop(installer_log, None)
            relay.paths = (installer_log, state_dir / "sb.log", state_dir / "tailscale.log")


if __name__ == "__main__":
    try:
        run_singbox(sys.argv[1])
    except Exception as exc:
        print(f"RuntimeError: sing-box startup failed: {redact(exc)}", flush=True)
        sys.exit(1)
