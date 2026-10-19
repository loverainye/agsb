"""Run official Tailscale binaries without root, TUN, or systemd."""

import fcntl
import hashlib
import http.client
import json
import os
import platform
import pwd
import shlex
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

import tailscale_state
from tailscale_support import redact, singbox_environment


VERSION = "1.104.1"
ARCHIVES = {
    "amd64": "108d1d96ecf410d305571e173516f27038f870919a9b89c914a167c6d33a4528",
    "arm64": "f60294374967f3dfd8cf57bbbd474d6cfce32d123e3a8ddeab82a87940daa806",
}
PID_FILE = "tailscaled.pid"
LAUNCHER_PID_FILE = "tailscale-launcher.pid"
READY_FILE = "tailscale-ready.json"
SOCKET_FILE = "tailscaled.sock"


def _digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def ensure_binaries(install_dir):
    """Install the pinned official archive, verifying before extracting files."""
    install_dir = Path(install_dir)
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if platform.system() != "Linux" or arch not in ARCHIVES:
        raise RuntimeError(f"Tailscale: unsupported platform {platform.system()}/{machine}")
    manifest = install_dir / "tailscale-binaries.json"
    try:
        saved = json.loads(manifest.read_text())
        if saved["version"] == VERSION and saved["arch"] == arch and all(
            _digest(install_dir / name) == saved["sha256"][name] for name in ("tailscale", "tailscaled")
        ):
            for name in ("tailscale", "tailscaled"):
                (install_dir / name).chmod(0o755)
            return
    except (OSError, KeyError, ValueError):
        pass
    install_dir.mkdir(parents=True, exist_ok=True)
    filename = f"tailscale_{VERSION}_{arch}.tgz"
    print(f"Tailscale: downloading official {VERSION}/{arch} from pkgs.tailscale.com", flush=True)
    with tempfile.TemporaryDirectory(prefix=".tailscale-download-", dir=install_dir) as temporary:
        temporary = Path(temporary)
        archive = temporary / filename
        with urllib.request.urlopen(f"https://pkgs.tailscale.com/stable/{filename}", timeout=60) as response, archive.open("wb") as stream:
            while block := response.read(1024 * 1024):
                stream.write(block)
        if _digest(archive) != ARCHIVES[arch]:
            raise RuntimeError("Tailscale: archive SHA-256 mismatch; installation stopped")
        hashes = {}
        with tarfile.open(archive, "r:gz") as tar:
            for name in ("tailscale", "tailscaled"):
                member = tar.getmember(f"tailscale_{VERSION}_{arch}/{name}")
                if not member.isfile():
                    raise RuntimeError("Tailscale: invalid binary archive")
                target = temporary / name
                with tar.extractfile(member) as source, target.open("wb") as destination:
                    while block := source.read(1024 * 1024):
                        destination.write(block)
                hashes[name] = _digest(target)
                target.chmod(0o755)
        for name in hashes:
            os.replace(temporary / name, install_dir / name)
        tailscale_state._write_private(manifest, json.dumps({"version": VERSION, "arch": arch, "sha256": hashes}).encode())
    print(f"Tailscale: official {VERSION} binaries verified and installed", flush=True)


def cli(install_dir, *arguments, input_value=None, timeout=20, check=True):
    install_dir = Path(install_dir)
    command = [str(install_dir / "tailscale"), f"--socket={install_dir / SOCKET_FILE}", *arguments]
    result = subprocess.run(command, input=input_value, capture_output=True, text=True,
                            timeout=timeout, env=singbox_environment())
    if check and result.returncode:
        raise RuntimeError(f"Tailscale: {arguments[0]} failed: " + redact(result.stderr or result.stdout))
    return result


def status(install_dir):
    result = cli(install_dir, "status", "--json", check=False, timeout=10)
    try:
        return json.loads(result.stdout)
    except ValueError:
        return {}


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("local-tailscaled.sock", timeout=15)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def local_api(install_dir, method, payload=None):
    connection = _UnixHTTPConnection(Path(install_dir) / SOCKET_FILE)
    try:
        connection.request(method, "/localapi/v0/prefs",
                           None if payload is None else json.dumps(payload),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read().decode(errors="replace")
        if response.status != 200:
            raise RuntimeError("Tailscale: local preferences request failed: " + redact(body))
        return json.loads(body)
    finally:
        connection.close()


def prepare_state(install_dir, settings):
    directory = Path(install_dir) / "tailscale"
    if directory.is_symlink():
        raise ValueError("Tailscale: state directory must not be a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    if settings.get("state_snapshot"):
        if settings["ephemeral"]:
            raise ValueError("Tailscale: restoring identity requires ephemeral=false")
        restored = tailscale_state.restore_state(directory)
        print("Tailscale: " + ("identity restored from encrypted snapshot" if restored else "reusing newer local identity"), flush=True)
    # sing-box kept host keys in the state root; official tailscaled uses ssh/.
    # Keep the old fingerprint and preserve any newer keys already in ssh/.
    ssh_dir = directory / "ssh"
    if ssh_dir.is_symlink() or (ssh_dir.exists() and not ssh_dir.is_dir()):
        raise ValueError("Tailscale: unsafe SSH identity directory")
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    ssh_dir.chmod(0o700)
    for source in directory.glob("ssh_host_*_key"):
        target = ssh_dir / source.name
        if source.is_symlink() or not source.is_file() or target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError("Tailscale: unsafe SSH host key file")
        if not target.exists():
            tailscale_state._write_private(target, source.read_bytes())
        target.chmod(0o600)
    return directory


def configure(install_dir, settings):
    state = status(install_dir)
    key = os.environ.get("TAILSCALE_AUTH_KEY", "").strip()
    needs_login = state.get("BackendState") in (None, "NoState", "NeedsLogin")
    if needs_login and not key:
        raise RuntimeError("Tailscale: restored node needs login; check node expiry or supply TAILSCALE_AUTH_KEY")
    if needs_login:
        # The key is read from stdin and never enters argv or a file.
        cli(install_dir, "up", "--timeout=45s", "--auth-key=file:/dev/stdin", input_value=key, timeout=55)
    else:
        # `up --timeout` is not a bare up and may reject restored preferences.
        # Change only WantRunning, preserving the existing identity and routes.
        local_api(install_dir, "PATCH", {"WantRunning": True, "WantRunningSet": True})
    cli(install_dir, "set", "--advertise-connector", "--ssh",
        "--accept-dns=false", "--accept-routes=false", f"--hostname={settings['hostname']}")
    prefs = local_api(install_dir, "GET")
    # Re-setting exit-node advertisement clears the connector's learned route
    # cache in Tailscale. Only add the default routes when they are missing.
    if not {"0.0.0.0/0", "::/0"}.issubset(prefs.get("AdvertiseRoutes") or []):
        cli(install_dir, "set", "--advertise-exit-node")
    # `tailscale set` has no --advertise-tags. Patch only tags, without reset.
    if settings["advertise_tags"]:
        local_api(install_dir, "PATCH", {
            "AdvertiseTags": settings["advertise_tags"], "AdvertiseTagsSet": True,
        })
    deadline = time.monotonic() + 45
    while True:
        current = status(install_dir)
        backend = current.get("BackendState", "unknown")
        if backend == "Running":
            return current
        if backend in ("NeedsLogin", "NeedsMachineAuth") or time.monotonic() >= deadline:
            raise RuntimeError(f"Tailscale: node not ready ({backend}); inspect tailscale.log and admin device approval")
        time.sleep(0.5)


def run(install_dir):
    install_dir = Path(install_dir).resolve()
    config = json.loads((install_dir / "config.json").read_text())
    settings = config.get("tailscale")
    if not settings:
        return
    os.umask(0o077)
    ready = install_dir / READY_FILE
    with (install_dir / "tailscale.lock").open("a") as lock:
        deadline = time.monotonic() + 15
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Tailscale: previous launcher is still running")
                time.sleep(0.2)
        ready.unlink(missing_ok=True)
        directory = prepare_state(install_dir, settings)
        # A private socket prevents mixing with the client's system tailscaled.
        arguments = [str(install_dir / "tailscaled"), "--tun=userspace-networking",
                     f"--socket={install_dir / SOCKET_FILE}", f"--statedir={directory}",
                     f"--state={'mem:' if settings['ephemeral'] else directory / 'tailscaled.state'}",
                     "--encrypt-state=false", "--port=0", "--no-logs-no-support"]
        environment = singbox_environment()
        environment["TS_LOGS_DIR"] = str(directory)
        print("Tailscale: starting official tailscaled in userspace-networking mode", flush=True)
        process = subprocess.Popen(arguments, env=environment, cwd=install_dir)
        pid_file = install_dir / PID_FILE
        tailscale_state._write_private(pid_file, str(process.pid).encode())

        def terminate(signum, frame):
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"Tailscale: tailscaled exited with code {process.returncode}")
                if (install_dir / SOCKET_FILE).exists() and status(install_dir).get("BackendState"):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Tailscale: local API startup timed out")
                time.sleep(0.2)
            current = configure(install_dir, settings)
            username = pwd.getpwuid(os.getuid()).pw_name
            host = current.get("Self", {}).get("DNSName", "").rstrip(".") or settings["hostname"]
            addresses = current.get("TailscaleIPs", [])
            print(f"Tailscale: node online; addresses={', '.join(addresses)}; hostname={host}", flush=True)
            print(f"Tailscale SSH connection: ssh {shlex.quote(username + '@' + host)}", flush=True)
            port = int(config.get("singbox_port", config["port_vm_ws"]))
            print(f"Tailscale: userspace TCP {port} reaches 127.0.0.1:{port}; VMess authentication still applies", flush=True)
            print("Tailscale: --advertise-connector and --advertise-exit-node enabled; approve exit routes in the admin console", flush=True)
            print("Tailscale: assign a connector tag and configure Apps/domains, route approvals and grants in the admin console", flush=True)
            print("Tailscale: SSH policy must allow this user; ACL/grants control access to local service ports", flush=True)
            tailscale_state._write_private(ready, json.dumps({"settings": settings, "port": port, "ips": addresses}).encode())
            result = process.wait()
            raise RuntimeError(f"Tailscale: tailscaled exited with code {result}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            ready.unlink(missing_ok=True)
            pid_file.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        run(sys.argv[1])
    except Exception as exc:
        print(f"Tailscale: startup failed: {redact(exc)}", flush=True)
        raise SystemExit(1)
