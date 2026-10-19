import contextlib
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import tailscale_daemon as daemon


KEY = "tskey-auth-synthetic-test-only"
SETTINGS = {"hostname": "streamlit-agsb", "ephemeral": False, "advertise_tags": []}
ONLINE = {"BackendState": "Running", "TailscaleIPs": ["100.64.0.1"],
          "Self": {"DNSName": "streamlit-agsb.example.ts.net."}}


class DaemonTests(unittest.TestCase):
    def test_verified_archive_cache_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                for name in ("tailscale", "tailscaled"):
                    data = (name + "-test-binary").encode()
                    member = tarfile.TarInfo(f"tailscale_{daemon.VERSION}_amd64/{name}")
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            blob = archive.getvalue()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(daemon.platform, "machine", return_value="x86_64"), patch.object(daemon.platform, "system", return_value="Linux"), patch.dict(daemon.ARCHIVES, {"amd64": digest}):
                with patch.object(daemon.urllib.request, "urlopen", return_value=io.BytesIO(blob)) as download:
                    daemon.ensure_binaries(root)
                    self.assertTrue(download.call_args.args[0].startswith("https://pkgs.tailscale.com/stable/"))
                binary_dir = root / daemon.BINARY_DIR
                self.assertEqual((binary_dir / "tailscale").read_bytes(), b"tailscale-test-binary")
                # Reproduce the deployed failure: the previous installer put
                # its executable at the exact path needed for node state.
                (root / "tailscale").write_bytes(b"tailscale-test-binary")
                with patch.object(daemon.urllib.request, "urlopen", side_effect=AssertionError("cache should be reused")):
                    daemon.ensure_binaries(root)
                    node_dir = daemon.prepare_state(root, SETTINGS)
                    identity = node_dir / "tailscaled.state"
                    identity.write_text("existing-node-identity")
                    daemon.ensure_binaries(root)
                    self.assertEqual(identity.read_text(), "existing-node-identity")
                self.assertTrue(node_dir.is_dir())
                self.assertEqual((binary_dir / "tailscale-legacy").read_bytes(), b"tailscale-test-binary")
                self.assertEqual((binary_dir / "tailscaled").stat().st_mode & 0o777, 0o755)
                (binary_dir / "tailscaled").write_bytes(b"damaged")
                with patch.object(daemon.urllib.request, "urlopen", return_value=io.BytesIO(b"bad archive")):
                    with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                        daemon.ensure_binaries(root)
                self.assertEqual((binary_dir / "tailscale").read_bytes(), b"tailscale-test-binary")

    def test_unknown_file_at_state_path_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / daemon.BINARY_DIR).mkdir()
            (root / daemon.BINARY_DIR / "tailscale").write_bytes(b"verified-binary")
            legacy = root / "tailscale"
            legacy.write_text("unrelated-user-data")
            with self.assertRaisesRegex(ValueError, "unknown file"):
                daemon.prepare_state(root, SETTINGS)
            self.assertEqual(legacy.read_text(), "unrelated-user-data")

    def test_cli_key_only_on_stdin_and_failures_redacted(self):
        env = {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_STATE_KEY": "test-encryption-key", "AGK": "test-tunnel-token", "SUDO_UID": "12345"}
        with patch.dict(os.environ, env, clear=True), patch.object(daemon.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "invalid " + KEY)) as run:
            with self.assertRaises(RuntimeError) as error:
                daemon.cli(Path("/tmp/test-install"), "up", "--auth-key=file:/dev/stdin", input_value=KEY)
            self.assertNotIn(KEY, str(error.exception))
            self.assertNotIn(KEY, str(run.call_args.args))
            self.assertEqual(run.call_args.args[0][0], "/tmp/test-install/bin/tailscale")
            self.assertEqual(run.call_args.kwargs["input"], KEY)
            for name in env:
                self.assertNotIn(name, run.call_args.kwargs["env"])

    def test_new_node_configures_connector_and_exit_node_then_logs_in(self):
        with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True), patch.object(daemon, "status", side_effect=[{"BackendState": "NeedsLogin"}, ONLINE]), patch.object(daemon, "cli") as cli, patch.object(daemon, "local_api", return_value={"AdvertiseRoutes": []}) as api:
            settings = {**SETTINGS, "advertise_tags": ["tag:app-connector"]}
            self.assertEqual(daemon.configure(Path("/tmp/test"), settings), ONLINE)
            self.assertIn("--advertise-connector", cli.call_args_list[0].args)
            self.assertIn("--ssh", cli.call_args_list[0].args)
            self.assertIn("--advertise-exit-node", cli.call_args_list[1].args)
            self.assertEqual(api.call_args_list[-3].args[2], {"AdvertiseTags": ["tag:app-connector"], "AdvertiseTagsSet": True})
            login = api.call_args_list[-2]
            self.assertEqual(login.args[1:], ("POST", {"AuthKey": KEY}))
            self.assertEqual(login.kwargs, {"resource": "start"})
            self.assertEqual(api.call_args.kwargs, {"resource": "login-interactive"})
            self.assertNotIn(KEY, str(cli.call_args_list))

    def test_login_local_api_preserves_preferences_and_handles_empty_response(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 204
        response.read.return_value = b""
        with patch.object(daemon, "_UnixHTTPConnection", return_value=connection):
            self.assertEqual(daemon.local_api(Path("/tmp/test"), "POST", {"AuthKey": KEY}, resource="start"), {})
        request = connection.request.call_args
        self.assertEqual(request.args[:2], ("POST", "/localapi/v0/start"))
        self.assertEqual(json.loads(request.args[2]), {"AuthKey": KEY})
        connection.close.assert_called_once()

    def test_login_local_api_errors_do_not_expose_auth_key(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 500
        response.read.return_value = ("invalid key: " + KEY).encode()
        with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True), patch.object(daemon, "_UnixHTTPConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "local start request failed") as error:
                daemon.local_api(Path("/tmp/test"), "POST", {"AuthKey": KEY}, resource="start")
        self.assertNotIn(KEY, str(error.exception))
        connection.close.assert_called_once()

    def test_starting_restored_node_waits_without_using_auth_key(self):
        states = [{"BackendState": "NoState"}, {"BackendState": "NeedsLogin", "HaveNodeKey": True}, {"BackendState": "Starting"}, ONLINE]
        with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True), patch.object(daemon, "status", side_effect=states), patch.object(daemon, "cli") as cli, patch.object(daemon, "local_api", return_value={"AdvertiseRoutes": ["0.0.0.0/0", "::/0"]}) as api, patch.object(daemon.time, "sleep"):
            self.assertEqual(daemon.configure(Path("/tmp/test"), SETTINGS), ONLINE)
            self.assertEqual(cli.call_count, 1)
            self.assertTrue(all(call.args[1] != "POST" for call in api.call_args_list))

    def test_restored_node_reauthenticates_only_after_startup_grace(self):
        states = [{"BackendState": "NeedsLogin", "HaveNodeKey": True}] * 2 + [ONLINE]
        with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True), patch.object(daemon, "status", side_effect=states), patch.object(daemon, "cli"), patch.object(daemon, "local_api", return_value={"AdvertiseRoutes": ["0.0.0.0/0", "::/0"]}) as api, patch.object(daemon.time, "sleep"), patch.object(daemon.time, "monotonic", side_effect=[0, 0, 5]):
            self.assertEqual(daemon.configure(Path("/tmp/test"), SETTINGS), ONLINE)
            login = [call for call in api.call_args_list if call.args[1] == "POST"]
            self.assertEqual(len(login), 1)
            self.assertEqual(login[0].args[2], {"AuthKey": KEY})

    def test_restored_node_preserves_login_tags_and_learned_routes(self):
        prefs = {"AdvertiseRoutes": ["0.0.0.0/0", "::/0", "203.0.113.1/32"]}
        with patch.dict(os.environ, {}, clear=True), patch.object(daemon, "status", return_value=ONLINE), patch.object(daemon, "cli") as cli, patch.object(daemon, "local_api", return_value=prefs) as api:
            daemon.configure(Path("/tmp/test"), SETTINGS)
            self.assertEqual(cli.call_count, 1)
            self.assertNotIn("up", cli.call_args.args)
            self.assertNotIn("--advertise-exit-node", cli.call_args.args)
            self.assertNotIn("--reset", cli.call_args.args)
            self.assertEqual(api.call_args_list[0].args[2], {"WantRunning": True, "WantRunningSet": True})
            self.assertEqual(api.call_count, 2)

    def test_missing_auth_and_device_approval_report_actionable_failure(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(daemon, "status", return_value={"BackendState": "NeedsLogin"}), patch.object(daemon, "cli"), patch.object(daemon, "local_api", return_value={"AdvertiseRoutes": []}) as api:
            with self.assertRaisesRegex(RuntimeError, "TAILSCALE_AUTH_KEY"):
                daemon.configure(Path("/tmp/test"), SETTINGS)
            self.assertTrue(all(call.args[1] != "POST" for call in api.call_args_list))
        with patch.object(daemon, "status", return_value={"BackendState": "NeedsMachineAuth"}), patch.object(daemon, "cli"), patch.object(daemon, "local_api", return_value={"AdvertiseRoutes": ["0.0.0.0/0", "::/0"]}):
            with self.assertRaisesRegex(RuntimeError, "admin device approval"):
                daemon.configure(Path("/tmp/test"), SETTINGS)

    def test_supervisor_restores_before_spawn_reports_ready_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.json").write_text(json.dumps({"tailscale": SETTINGS, "port_vm_ws": 21111}))
            (root / daemon.SOCKET_FILE).touch()
            prepared = root / "tailscale"
            prepared.mkdir()
            process = Mock(pid=12345)
            process.poll.return_value = None

            def spawned(arguments, **kwargs):
                restore.assert_called_once()
                self.assertEqual(arguments[0], str(root / "bin" / "tailscaled"))
                self.assertIn("--tun=userspace-networking", arguments)
                self.assertIn(f"--state={prepared}/tailscaled.state", arguments)
                self.assertNotIn("TAILSCALE_AUTH_KEY", kwargs["env"])
                return process

            def exited():
                ready = json.loads((root / daemon.READY_FILE).read_text())
                self.assertEqual(ready["port"], 21111)
                self.assertEqual(ready["ips"], ["100.64.0.1"])
                process.poll.return_value = 0
                return 0

            process.wait.side_effect = exited
            with patch.object(daemon, "prepare_state", return_value=prepared) as restore, patch.object(daemon.subprocess, "Popen", side_effect=spawned), patch.object(daemon, "status", return_value=ONLINE), patch.object(daemon, "configure", return_value=ONLINE), patch.object(daemon.signal, "signal"), patch.object(daemon.os, "umask"), contextlib.redirect_stdout(io.StringIO()) as captured:
                with self.assertRaisesRegex(RuntimeError, "exited with code 0"):
                    daemon.run(root)
            self.assertIn("Tailscale SSH connection: ssh", captured.getvalue())
            self.assertIn("127.0.0.1:21111", captured.getvalue())
            self.assertFalse((root / daemon.READY_FILE).exists())
            self.assertFalse((root / daemon.PID_FILE).exists())

    def test_supervisor_terminates_daemon_on_configuration_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = {**SETTINGS, "ephemeral": True}
            (root / "config.json").write_text(json.dumps({"tailscale": settings, "port_vm_ws": 19999}))
            (root / daemon.SOCKET_FILE).touch()
            process = Mock(pid=12345)
            process.poll.return_value = None
            with patch.object(daemon, "prepare_state", return_value=root), patch.object(daemon.subprocess, "Popen", return_value=process) as spawn, patch.object(daemon, "status", return_value=ONLINE), patch.object(daemon, "configure", side_effect=RuntimeError("approval failed")), patch.object(daemon.signal, "signal"), patch.object(daemon.os, "umask"):
                with self.assertRaisesRegex(RuntimeError, "approval failed"):
                    daemon.run(root)
            self.assertIn("--state=mem:", spawn.call_args.args[0])
            process.terminate.assert_called_once()
            self.assertFalse((root / daemon.READY_FILE).exists())
            self.assertFalse((root / daemon.PID_FILE).exists())


if __name__ == "__main__":
    unittest.main()
