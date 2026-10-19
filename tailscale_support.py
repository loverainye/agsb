"""Cloudflare Tunnel and Tailscale SSH in the existing sing-box process."""

import hashlib
import json
import os
import pwd
import re
import shlex
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import tailscale_state


TAILSCALE_TAG = "tailscale-proxy"
CLOUDFLARE_TAG = "cloudflare-tunnel"
_RELAYS = {}
_RELAY_LOCK = threading.Lock()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _is_tailscale_endpoint(endpoint):
    # Existing on-disk templates can still carry the previous endpoint tag.
    return endpoint.get("type") == "tailscale" or endpoint.get("tag") in (TAILSCALE_TAG, "tailscale-ssh")


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
    # Detect key changes without persisting the key itself.
    settings = {
        "hostname": hostname.lower(),
        "ephemeral": ephemeral in ("true", "1"),
        "auth_key_hash": hashlib.sha256(key.encode()).hexdigest(),
        # Reconfigure existing SSH-only installations on the next app run.
        "proxy_forwarding": True,
        # Regenerate cached templates when the endpoint tag changes.
        "endpoint_tag": TAILSCALE_TAG,
    }
    if snapshot_hash:
        settings["state_snapshot"] = snapshot_hash
    return settings


def prepare_endpoint_directories(endpoint, install_dir):
    """Create directories as the app user before sing-box's mkdir/chown path."""
    install_dir = Path(install_dir).resolve()
    state_dir = Path(endpoint.get("state_directory") or "tailscale")
    if not state_dir.is_absolute():
        state_dir = install_dir / state_dir
    taildrop_dir = Path(endpoint.get("taildrop_directory") or state_dir / "taildrop")
    if not taildrop_dir.is_absolute():
        taildrop_dir = install_dir / taildrop_dir
    for directory in (state_dir, taildrop_dir):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    endpoint["state_directory"] = str(state_dir.resolve())
    endpoint["taildrop_directory"] = str(taildrop_dir.resolve())


def add_endpoint(config, settings, install_dir):
    if settings is None:
        return
    endpoint = {
        "type": "tailscale",
        "tag": TAILSCALE_TAG,
        "hostname": settings["hostname"],
        "ephemeral": settings["ephemeral"],
        "system_interface": False,
        "ssh_server": True,
    }
    prepare_endpoint_directories(endpoint, install_dir)
    config.setdefault("endpoints", []).append(endpoint)
    # The endpoint resolves control-plane/DERP hosts with the container DNS.
    _add_local_resolver(config)
    rules = config["route"].setdefault("rules", [])
    for inbound in config.get("inbounds", []):
        if inbound.get("tag") == "vmess-in" and inbound.get("type") == "vmess":
            port = int(inbound["listen_port"])
            if port == 22:
                raise ValueError("PORT=22 conflicts with Tailscale SSH; choose another VMess port")
            # The endpoint maps its own Tailscale IPv4/IPv6 destinations to
            # 127.0.0.1/::1. Route both to the existing IPv4 VMess listener.
            rules.append({
                "inbound": [TAILSCALE_TAG],
                "network": "tcp",
                "ip_cidr": ["127.0.0.1/32", "::1/128"],
                "port": [port],
                "action": "route",
                "outbound": "direct",
                "override_address": "127.0.0.1",
                "override_port": port,
            })
            print(f"Tailscale: forwarding tailnet TCP port {port} to 127.0.0.1:{port}; VMess/WebSocket authentication still applies", flush=True)
            break
    # SSH is intercepted inside the endpoint, before sing-box routing.
    rules.append({"inbound": [TAILSCALE_TAG], "action": "reject"})
    # tsnet's authentication and state diagnostics are emitted at debug level.
    config["log"]["level"] = "debug"


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
    for endpoint in result.get("endpoints", []):
        if _is_tailscale_endpoint(endpoint):
            key = env.get("TAILSCALE_AUTH_KEY", "").strip()
            if key:
                endpoint["auth_key"] = key
            elif env.get(tailscale_state.KEY_ENV, "").strip():
                # A restored identity can authenticate without a bootstrap key.
                tailscale_state.load_snapshot(env)
                endpoint.pop("auth_key", None)
            else:
                raise ValueError("TAILSCALE_AUTH_KEY is required to start the configured Tailscale endpoint")
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
    if any(_is_tailscale_endpoint(item) for item in config.get("endpoints", [])):
        features.append(("Tailscale", "with_tailscale"))
    child_env = singbox_environment()
    version = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=15, env=child_env)
    match = re.search(r"sing-box version (\d+)\.(\d+)\.(\d+)([^\s]*)", version.stdout)
    if version.returncode or not match or tuple(map(int, match.group(1, 2, 3))) < (1, 14, 0):
        raise RuntimeError("Cloudflare Tunnel / Tailscale SSH requires sing-box >= 1.14.0")
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
    for endpoint in config.get("endpoints", []):
        if _is_tailscale_endpoint(endpoint):
            prepare_endpoint_directories(endpoint, install_dir)
            if os.environ.get(tailscale_state.KEY_ENV, "").strip() or tailscale_state.SNAPSHOT_PATH.exists():
                if endpoint.get("ephemeral", False):
                    raise ValueError("Tailscale: encrypted identity restore requires ephemeral=false")
                restored = tailscale_state.restore_state(endpoint["state_directory"])
                status = "restored from encrypted snapshot" if restored else "reusing newer local state for the saved identity"
                print(f"Tailscale: {status}; state directory={endpoint['state_directory']}", flush=True)
            print("Tailscale: state and Taildrop directories prepared by the app user (0700)", flush=True)
    payload = runtime_config(config).encode()
    if any(item.get("tag") == CLOUDFLARE_TAG for item in config.get("inbounds", [])):
        print("Cloudflare: starting Tunnel in the existing sing-box process; token injected from AGK", flush=True)
        print("Cloudflare: connection and ingress diagnostics are in sb.log; startup does not yet confirm edge registration", flush=True)
    for endpoint in config.get("endpoints", []):
        if _is_tailscale_endpoint(endpoint):
            username = pwd.getpwuid(os.getuid()).pw_name
            command = f"ssh {shlex.quote(username + '@' + endpoint['hostname'])}"
            print(f"Tailscale: starting SSH in the existing sing-box process; user={username}", flush=True)
            print(f"Tailscale SSH connection: {command}", flush=True)
            print("Tailscale: connect after the node is online; the client must join the tailnet and SSH policy must allow this user", flush=True)
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
        self.paths = (installer_log, state_dir / "sb.log")
        self.positions = {}
        self.pending = {}
        self.sb_pid = self._pid()
        for path in self.paths:
            try:
                stat = path.stat()
                self.positions[path] = (stat.st_ino, stat.st_size)
            except OSError:
                pass
        self.stop = threading.Event()

    def _pid(self):
        try:
            return (self.state_dir / "sbpid.log").read_text().strip()
        except OSError:
            return None

    def poll(self):
        pid = self._pid()
        if pid != self.sb_pid:
            self.positions.pop(self.state_dir / "sb.log", None)
            self.pending.pop(self.state_dir / "sb.log", None)
            self.sb_pid = pid
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
                    if ("Tailscale" in message or "endpoint/tailscale[" in message
                            or "Cloudflare:" in message or "inbound/cloudflared[" in message
                            or "FATAL" in message or "Traceback" in message
                            or "Error:" in message or "失败" in message or "错误" in message):
                        # Routine network dial messages would overwhelm app logs.
                        if not any(text in message for text in (
                            "output connection to", "output packet connection",
                            "inbound connection to", "inbound packet connection to",
                        )):
                            print(message, flush=True)
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
            relay.paths = (installer_log, state_dir / "sb.log")


if __name__ == "__main__":
    try:
        run_singbox(sys.argv[1])
    except Exception as exc:
        print(f"RuntimeError: sing-box startup failed: {redact(exc)}", flush=True)
        sys.exit(1)
