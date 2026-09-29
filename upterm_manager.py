import base64
import binascii
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


UPTERM_VERSION = "v0.33.0"
BUNDLE_DIR = Path(__file__).resolve().parent / "bin"
BUNDLED_BINARIES = {
    "x86_64": ("upterm-linux-amd64", "2223fd2388abe4a72aa38ddbfe4b342c155db8248573ac6bd65b64b054b1609d"),
    "aarch64": ("upterm-linux-arm64", "590c850ee5229b3fd9fca4657df8afd40d45a02f00c4fb7943ad9148b2b3d997"),
}
SERVER = "wss://uptermd.upterm.dev"
KNOWN_HOSTS = (
    "@cert-authority uptermd.upterm.dev ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4\n"
    "@cert-authority [uptermd.upterm.dev]:443 ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAICiecex8Dq718eSe1CCLgLvDmI7AagvCtax7brPFWkh4\n"
)


def _file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_public_key(line):
    parts = line.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        return False
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(blob) < 8:
        return False
    key_type_size = int.from_bytes(blob[:4], "big")
    return blob[4:4 + key_type_size] == parts[0].encode("ascii") and len(blob) > 4 + key_type_size


class UptermManager:
    def __init__(self, home=None):
        self.home = Path(home or Path.home())
        self.state_dir = self.home / ".agsb"
        self.path = None
        self.session_file = self.state_dir / "upterm_session.json"
        self.known_hosts_file = self.state_dir / "upterm_known_hosts"
        self.connection_command = None
        self.reused_process = False

    def prepare(self):
        try:
            configured = os.environ.get("UPTERM_BIN", "").strip()
            self.path = Path(configured).expanduser().resolve() if configured else self._install_bundled_binary()
            if not self.path.is_file() or not os.access(self.path, os.X_OK):
                raise ValueError(f"Upterm executable is unavailable: {self.path}")
            self._ensure_known_hosts()
            print(f"Upterm: executable ready at {self.path}", flush=True)
            return True
        except (OSError, ValueError) as exc:
            print(f"Upterm: setup failed: {type(exc).__name__}: {exc}", flush=True)
            return False

    def _install_bundled_binary(self):
        if platform.system().lower() != "linux":
            raise ValueError("Bundled Upterm executables support Linux only")
        machine = platform.machine().lower()
        architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
        if architecture not in BUNDLED_BINARIES:
            raise ValueError(f"Unsupported Upterm architecture: {machine}")
        filename, expected_hash = BUNDLED_BINARIES[architecture]
        source = BUNDLE_DIR / filename
        if not source.is_file():
            raise ValueError(f"Bundled Upterm executable is missing: {source}")
        if _file_sha256(source) != expected_hash:
            raise ValueError(f"Bundled Upterm executable checksum mismatch: {source}")
        destination = self.home / "upterm"
        if (destination.is_file() and not destination.is_symlink()
                and os.access(destination, os.X_OK) and _file_sha256(destination) == expected_hash):
            print(f"Upterm: using verified cached {UPTERM_VERSION} executable", flush=True)
            return destination
        self.home.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".upterm-", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as bundled:
                shutil.copyfileobj(bundled, output, length=1024 * 1024)
            if _file_sha256(Path(temporary)) != expected_hash:
                raise ValueError("Copied Upterm executable checksum mismatch")
            os.chmod(temporary, 0o755)
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(f"Upterm: copied bundled {UPTERM_VERSION} linux/{architecture} to {destination}", flush=True)
        return destination

    def _ensure_known_hosts(self):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.known_hosts_file.exists():
            if self.known_hosts_file.read_text(encoding="ascii") != KNOWN_HOSTS:
                raise ValueError(f"Upterm relay host key pin differs: {self.known_hosts_file}")
            return
        descriptor = os.open(self.known_hosts_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(KNOWN_HOSTS)

    def _authorization_args(self):
        user = os.environ.get("UPTERM_AUTHORIZED_USER", "").strip()
        key = os.environ.get("UPTERM_AUTHORIZED_KEY", "").strip()
        key_file = os.environ.get("UPTERM_AUTHORIZED_KEYS", "").strip()
        arguments = []
        identities = {"user": user}
        if user:
            if "\n" in user or "\r" in user:
                raise ValueError("UPTERM_AUTHORIZED_USER must contain one account")
            arguments.extend(["--authorized-user", user])
        if key and key_file:
            raise ValueError("Set either UPTERM_AUTHORIZED_KEY or UPTERM_AUTHORIZED_KEYS, not both")
        if key:
            if "\n" in key or "\r" in key:
                raise ValueError("UPTERM_AUTHORIZED_KEY must contain one public key")
            if not _valid_public_key(key):
                raise ValueError("UPTERM_AUTHORIZED_KEY must be a public SSH key")
            key_path = self.state_dir / "upterm_authorized_keys"
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(key + "\n")
            arguments.extend(["--authorized-keys", str(key_path)])
            identities["keys_sha256"] = hashlib.sha256(key.encode("utf-8")).hexdigest()
        elif key_file:
            key_path = Path(key_file).expanduser().resolve()
            if not key_path.is_file():
                raise ValueError(f"UPTERM_AUTHORIZED_KEYS does not exist: {key_path}")
            key_data = key_path.read_bytes()
            active_lines = [line.strip() for line in key_data.decode("utf-8").splitlines()
                            if line.strip() and not line.lstrip().startswith("#")]
            if not active_lines:
                raise ValueError("UPTERM_AUTHORIZED_KEYS contains no public keys")
            if not all(_valid_public_key(line) for line in active_lines):
                raise ValueError("UPTERM_AUTHORIZED_KEYS contains an invalid public key")
            arguments.extend(["--authorized-keys", str(key_path)])
            identities["keys_sha256"] = hashlib.sha256(key_data).hexdigest()
        fingerprint = hashlib.sha256(json.dumps(identities, sort_keys=True).encode("ascii")).hexdigest()
        return arguments, fingerprint

    def _run(self, arguments, timeout):
        retained = (
            "PATH", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TERM",
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "ALL_PROXY",
            "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
            "SSH_AUTH_SOCK",
        )
        environment = {name: os.environ[name] for name in retained if name in os.environ}
        environment["HOME"] = str(self.home)
        return subprocess.run(
            [str(self.path), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=environment,
        )

    @staticmethod
    def _log_diagnostics(result):
        for line in result.stderr.splitlines()[-20:]:
            print(f"[upterm] {line[:2000]}", flush=True)

    def _log_connection(self, session):
        command = session.get("sshCommand")
        if (session.get("status") != "ready" or not isinstance(command, str)
                or not command.startswith("ssh ") or len(command) > 2000
                or "\n" in command or "\r" in command):
            print(f"Upterm: unexpected session status: {session.get('status')}", flush=True)
            return False
        try:
            arguments = shlex.split(command)
        except ValueError:
            arguments = []
        if (len(arguments) == 2 and arguments[0] == "ssh"):
            expected_host = "uptermd.upterm.dev"
        elif (len(arguments) == 4 and arguments[:2] == ["ssh", "-o"]
              and arguments[2].startswith("ProxyCommand=upterm proxy wss://")):
            expected_host = "uptermd.upterm.dev:443"
        else:
            expected_host = None
        user, separator, host = arguments[-1].rpartition("@") if arguments else ("", "", "")
        if not separator or not user or host != expected_host:
            print("Upterm: cannot derive direct SSH command from session data", flush=True)
            return False
        self.connection_command = f"ssh {shlex.quote(user + '@uptermd.upterm.dev')}"
        print(f"Upterm SSH connection: {self.connection_command}", flush=True)
        return True

    def start(self):
        if self.path is None:
            raise RuntimeError("prepare() must be called before start()")
        try:
            authorization, auth_fingerprint = self._authorization_args()
            try:
                previous_state = json.loads(self.session_file.read_text(encoding="ascii"))
            except (OSError, ValueError, json.JSONDecodeError):
                previous_state = {}
            if not isinstance(previous_state, dict):
                previous_state = {}
            previous_name = previous_state.get("name", "")
            if isinstance(previous_name, str) and re.fullmatch(r"agsb-[0-9a-f]{12}", previous_name):
                if previous_state.get("authorization_sha256") != auth_fingerprint:
                    stopped = self._run(["session", "stop", previous_name], timeout=12)
                    if stopped.returncode not in (0, 4):
                        self._log_diagnostics(stopped)
                        raise ValueError("Could not stop the session using the previous authorization")
                    print("Upterm: authorization changed; previous session stopped", flush=True)
                else:
                    previous = self._run(["session", "info", previous_name, "-o", "json"], timeout=12)
                    if previous.returncode == 0:
                        session = json.loads(previous.stdout)
                        if session.get("status") == "ready" and self._log_connection(session):
                            self.reused_process = True
                            print("Upterm: existing session reused", flush=True)
                            return True
                print("Upterm: previous session is unavailable; starting a new one", flush=True)

            name = f"agsb-{secrets.token_hex(6)}"
            shell = os.environ.get("SHELL") or "/bin/bash"
            if not Path(shell).is_file() or not os.access(shell, os.X_OK):
                shell = "/bin/sh"
            arguments = [
                "host", "--detach", "--accept", "--output", "json",
                "--server", SERVER, "--known-hosts", str(self.known_hosts_file),
                "--name", name, *authorization, "--", shell,
            ]
            if not authorization:
                print("Upterm: anyone with the logged SSH connection command can join", flush=True)
            self.session_file.write_text(json.dumps({
                "name": name,
                "authorization_sha256": auth_fingerprint,
            }), encoding="ascii")
            print(f"Upterm: starting detached host via {SERVER}...", flush=True)
            result = self._run(arguments, timeout=90)
            self._log_diagnostics(result)
            if result.returncode != 0:
                print(f"Upterm: host failed with exit code {result.returncode}", flush=True)
                return False
            session = json.loads(result.stdout)
            if not self._log_connection(session):
                return False
            return True
        except subprocess.TimeoutExpired:
            print("Upterm: host timed out after 90 seconds; check relay connectivity", flush=True)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Upterm: session failed: {type(exc).__name__}: {exc}", flush=True)
        return False

    def cleanup(self):
        print("Upterm: session remains in the background", flush=True)
