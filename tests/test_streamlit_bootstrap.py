import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import tailscale_state
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.snapshot_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.snapshot_directory.cleanup)
        snapshot = patch.object(tailscale_state, "SNAPSHOT_PATH", Path(self.snapshot_directory.name) / "missing.enc")
        snapshot.start()
        self.addCleanup(snapshot.stop)

    def test_installer_starts_when_upterm_is_unavailable(self):
        launcher = load_script("launcher_install_first", "upload-yuancheng.py")
        identifier = "123e4567-e89b-12d3-a456-426614174000"
        with patch.object(launcher, "UptermManager") as manager_factory:
            with patch.object(launcher, "launch_installer") as installer:
                with patch.object(launcher.signal, "signal"):
                    manager = manager_factory.return_value
                    def prepare():
                        self.assertTrue(installer.called)
                        return False

                    manager.prepare.side_effect = prepare
                    installer.return_value.poll.return_value = None
                    self.assertFalse(launcher.main([
                        "--uuid", identifier, "--agk", "token", "--domain", "example.test"
                    ]))
                    installer.assert_called_once()
                    manager_factory.assert_called_once_with(home=launcher.USER_HOME)
                    manager.start.assert_not_called()

    def test_settings_use_port_environment(self):
        launcher = load_script("launcher", "upload-yuancheng.py")
        identifier = "123e4567-e89b-12d3-a456-426614174000"
        args = launcher.parse_args(
            ["--uuid", identifier, "--agk", "token", "--domain", "https://example.test/"]
        )
        with patch.dict(launcher.os.environ, {"PORT": "19999"}):
            self.assertEqual(
                launcher.resolve_settings(args),
                {"uuid": identifier, "port": 19999, "agk": "token", "domain": "example.test"},
            )

    def test_installer_receives_token_in_environment(self):
        launcher = load_script("launcher", "upload-yuancheng.py")
        identifier = "123e4567-e89b-12d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "agsb-v2.py").write_text("")
            launcher.USER_HOME = temp_path
            launcher.__file__ = str(temp_path / "upload-yuancheng.py")
            with patch.object(launcher, "start_log_relay"), patch.object(launcher, "_installer_already_started", return_value=False):
                with patch.object(launcher.subprocess, "Popen") as process:
                    process.return_value.pid = 12345
                    launcher.launch_installer(
                        {"uuid": identifier, "port": 49999, "agk": "private-token", "domain": "example.test"},
                    )
                    arguments, options = process.call_args
                    self.assertNotIn("private-token", " ".join(arguments[0]))
                    self.assertEqual(options["env"]["AGK"], "private-token")
                    self.assertIn("--no-autostart", arguments[0])
                    self.assertIn("--embedded-cloudflare", arguments[0])
                    self.assertEqual(arguments[0][arguments[0].index("--port") + 1], "49999")
                    self.assertNotIn("--ssh-file", arguments[0])
                    self.assertNotIn("--public-port", arguments[0])

    def test_old_gateway_install_is_not_reused_as_singbox_origin(self):
        launcher = load_script("launcher_old_gateway", "upload-yuancheng.py")
        identifier = "123e4567-e89b-12d3-a456-426614174000"
        settings = {"uuid": identifier, "port": 19999, "agk": "token", "domain": "example.test"}
        with tempfile.TemporaryDirectory() as temp_dir:
            launcher.USER_HOME = Path(temp_dir)
            state_dir = Path(temp_dir) / ".agsb"
            state_dir.mkdir()
            config_file = state_dir / "config.json"
            config = {
                "uuid_str": identifier,
                "port_vm_ws": 19999,
                "custom_domain_agn": "example.test",
                "ssh_file": "/tmp/old-session.txt",
            }
            config_file.write_text(json.dumps(config))
            self.assertFalse(launcher._installer_already_started(settings))

            config["ssh_file"] = None
            config_file.write_text(json.dumps(config))
            for name in ("sbpid.log", "sbargopid.log"):
                (state_dir / name).write_text("12345")
            with patch.object(launcher, "_is_running", return_value=True):
                # Migrate the old standalone connector even when it is alive.
                self.assertFalse(launcher._installer_already_started(settings))
                config["cloudflare"] = launcher.cloudflare_settings(settings["agk"])
                config_file.write_text(json.dumps(config))
                (state_dir / "sbargopid.log").unlink()
                self.assertTrue(launcher._installer_already_started(settings))

    def test_gateway_serves_file_and_relays_other_paths(self):
        installer = load_script("installer", "agsb-v2.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ssh_file = temp_path / "test.txt"
            upstream = socket.socket()
            upstream.bind(("127.0.0.1", 0))
            upstream.listen(1)
            upstream_port = upstream.getsockname()[1]
            with socket.socket() as port_probe:
                port_probe.bind(("127.0.0.1", 0))
                public_port = port_probe.getsockname()[1]
            installer.INSTALL_DIR = temp_path
            installer.GATEWAY_SCRIPT_FILE = temp_path / "gateway.py"
            gateway_script = installer.create_gateway_script(public_port, upstream_port, ssh_file)

            upstream_requests = []

            def answer_upstream():
                connection, _ = upstream.accept()
                with connection:
                    request = connection.recv(8192)
                    upstream_requests.append(request)
                    connection.sendall(
                        b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    )
                upstream.close()

            worker = threading.Thread(target=answer_upstream, daemon=True)
            worker.start()
            process = subprocess.Popen(
                [sys.executable, str(gateway_script)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                for _ in range(50):
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{public_port}/test.txt", timeout=1
                        ):
                            self.fail("missing SSH file should not return 200")
                    except urllib.error.HTTPError as exc:
                        self.assertEqual(exc.code, 503)
                        exc.close()
                        break
                    except OSError:
                        time.sleep(0.02)
                else:
                    self.fail("gateway did not start")
                ssh_file.write_text("ssh session@example\n")
                for _ in range(50):
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{public_port}/test.txt", timeout=1
                        ) as response:
                            self.assertEqual(response.read(), b"ssh session@example\n")
                        break
                    except OSError:
                        time.sleep(0.02)
                else:
                    self.fail("gateway did not start")
                with socket.create_connection(("127.0.0.1", public_port), timeout=2) as client:
                    client.sendall(
                        b"GET /vmess HTTP/1.1\r\nHost: example.test\r\n"
                        b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    )
                    self.assertIn(b"101 Switching Protocols", client.recv(8192))
            finally:
                process.terminate()
                process.wait(timeout=3)
                upstream.close()
                worker.join(timeout=1)
            self.assertEqual(len(upstream_requests), 1)
            self.assertIn(b"Upgrade: websocket", upstream_requests[0])

    def test_named_tunnel_uses_token_file(self):
        installer = load_script("installer", "agsb-v2.py")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            installer.INSTALL_DIR = temp_path
            installer.CONFIG_FILE = temp_path / "config.json"
            installer.SB_PID_FILE = temp_path / "sbpid.log"
            installer.ARGO_PID_FILE = temp_path / "sbargopid.log"
            installer.GATEWAY_PID_FILE = temp_path / "gatewaypid.log"
            installer.GATEWAY_SCRIPT_FILE = temp_path / "gateway.py"
            installer.TUNNEL_TOKEN_FILE = temp_path / "tunnel_token"
            installer.LOG_FILE = temp_path / "argo.log"
            installer.DEBUG_LOG = temp_path / "debug.log"
            installer.GATEWAY_SCRIPT_FILE.write_text("")
            installer.TUNNEL_TOKEN_FILE.write_text("private-token")
            installer.CONFIG_FILE.write_text(
                json.dumps(
                    {
                        "port_vm_ws": 49999,
                        "singbox_port": 50000,
                        "gateway_port": 49999,
                        "ssh_file": "/tmp/test.txt",
                        "argo_token": None,
                    }
                )
            )
            installer.create_startup_script()
            cf_script = (temp_path / "start_cf.sh").read_text()
            self.assertIn("--token-file", cf_script)
            self.assertNotIn("private-token", cf_script)
            self.assertEqual(subprocess.run(["bash", "-n", str(temp_path / "start_cf.sh")]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
