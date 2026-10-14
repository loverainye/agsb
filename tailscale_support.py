"""Tailscale SSH support for the existing sing-box process."""

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


TAILSCALE_TAG = "tailscale-ssh"
_RELAYS = {}
_RELAY_LOCK = threading.Lock()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def settings_from_env(uuid_value, environ=None):
    env = os.environ if environ is None else environ
    key = env.get("TAILSCALE_AUTH_KEY", "").strip()
    if not key:
        return None
    hostname = env.get("TAILSCALE_HOSTNAME", "").strip() or f"agsb-{uuid_value[:8]}"
    if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", hostname):
        raise ValueError("TAILSCALE_HOSTNAME must be a hostname of 1-63 letters, numbers or hyphens")
    ephemeral = env.get("TAILSCALE_EPHEMERAL", "true").strip().lower()
    if ephemeral not in ("true", "false", "1", "0"):
        raise ValueError("TAILSCALE_EPHEMERAL must be true or false")
    # Detect key changes without persisting the key itself.
    return {
        "hostname": hostname.lower(),
        "ephemeral": ephemeral in ("true", "1"),
        "auth_key_hash": hashlib.sha256(key.encode()).hexdigest(),
    }


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
    config["endpoints"] = [endpoint]
    # The endpoint resolves control-plane/DERP hosts with the container DNS.
    config["dns"] = {"servers": [{"type": "local", "tag": "local-dns"}], "final": "local-dns"}
    config["route"] = {
        "default_domain_resolver": "local-dns",
        "final": "direct",
        # SSH is intercepted inside the endpoint, before sing-box routing.
        "rules": [{"inbound": [TAILSCALE_TAG], "action": "reject"}],
    }
    # tsnet's authentication and state diagnostics are emitted at debug level.
    config["log"]["level"] = "debug"


def runtime_config(config, environ=None):
    """Copy the template and inject credentials only into the runtime JSON."""
    env = os.environ if environ is None else environ
    result = json.loads(json.dumps(config))
    for endpoint in result.get("endpoints", []):
        if endpoint.get("tag") == TAILSCALE_TAG:
            key = env.get("TAILSCALE_AUTH_KEY", "").strip()
            if not key:
                raise ValueError("TAILSCALE_AUTH_KEY is required to start the configured Tailscale endpoint")
            endpoint["auth_key"] = key
    return json.dumps(result)


def redact(message):
    message = _ANSI.sub("", str(message))
    for name in ("TAILSCALE_AUTH_KEY", "AGK", "agk"):
        secret = os.environ.get(name, "").strip()
        if secret:
            message = message.replace(secret, "[redacted]")
    return re.sub(r"tskey-[A-Za-z0-9_-]+", "[redacted]", message)


def singbox_environment():
    environment = os.environ.copy()
    # sing-box's CLI uses SUDO_* to select a file owner. Streamlit can inherit
    # these from its bootstrap while running as a different, unprivileged user.
    for name in ("TAILSCALE_AUTH_KEY", "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
        environment.pop(name, None)
    return environment


def validate_config(binary, config):
    child_env = singbox_environment()
    version = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=15, env=child_env)
    match = re.search(r"sing-box version (\d+)\.(\d+)\.(\d+)([^\s]*)", version.stdout)
    if version.returncode or not match or tuple(map(int, match.group(1, 2, 3))) < (1, 14, 0):
        raise RuntimeError("Tailscale SSH requires sing-box >= 1.14.0")
    if "with_tailscale" not in version.stdout:
        raise RuntimeError("sing-box was built without with_tailscale; Tailscale SSH is unavailable")
    checked = subprocess.run(
        [str(binary), "check", "-c", "stdin"], input=runtime_config(config),
        capture_output=True, text=True, timeout=20, env=child_env,
    )
    if checked.returncode:
        raise RuntimeError("Tailscale sing-box configuration check failed: " + redact(checked.stderr or checked.stdout))
    print(f"Tailscale: sing-box {match.group(0).split()[-1]} configuration check passed", flush=True)


def run_singbox(install_dir):
    """Replace this short-lived launcher with sing-box, retaining its PID."""
    install_dir = Path(install_dir).resolve()
    config = json.loads((install_dir / "sb.json").read_text())
    for endpoint in config.get("endpoints", []):
        if endpoint.get("tag") == TAILSCALE_TAG:
            prepare_endpoint_directories(endpoint, install_dir)
            print("Tailscale: state and Taildrop directories prepared by the app user (0700)", flush=True)
    payload = runtime_config(config).encode()
    for endpoint in config.get("endpoints", []):
        if endpoint.get("tag") == TAILSCALE_TAG:
            username = pwd.getpwuid(os.getuid()).pw_name
            command = f"ssh {shlex.quote(username + '@' + endpoint['hostname'])}"
            print(f"Tailscale: starting SSH in the existing sing-box process; user={username}", flush=True)
            print(f"Tailscale SSH connection: {command}", flush=True)
            print("Tailscale: connect after the node is online; the client must join the tailnet and SSH policy must allow this user", flush=True)
    child_env = singbox_environment()
    if any(name in os.environ for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID")):
        print("Tailscale: inherited sudo ownership metadata removed; files belong to the current app user", flush=True)
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
    def __init__(self, state_dir, installer_log):
        self.state_dir = state_dir
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
                    message = redact(line.decode("utf-8", errors="replace"))
                    if ("Tailscale" in message or "endpoint/tailscale[" in message
                            or "FATAL" in message or "RuntimeError:" in message):
                        # Routine network dial messages would overwhelm app logs.
                        if "output connection to" not in message and "output packet connection" not in message:
                            print(message, flush=True)
            except OSError:
                continue

    def run(self):
        while not self.stop.wait(0.5):
            self.poll()


def start_log_relay(state_dir, installer_log):
    """One daemon thread per app, reused across Streamlit reruns."""
    state_dir, installer_log = Path(state_dir), Path(installer_log)
    with _RELAY_LOCK:
        key = str(state_dir.resolve())
        relay = _RELAYS.get(key)
        if relay is None:
            relay = _LogRelay(state_dir, installer_log)
            threading.Thread(target=relay.run, name="tailscale-log-relay", daemon=True).start()
            _RELAYS[key] = relay
        elif relay.paths[0] != installer_log:
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
        print(f"Tailscale: sing-box startup failed: {redact(exc)}", flush=True)
        sys.exit(1)
