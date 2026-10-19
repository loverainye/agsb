import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import tailscale_support as tailscale


ROOT = Path(__file__).resolve().parents[1]
UUID = "123e4567-e89b-12d3-a456-426614174000"
KEY = "tskey-auth-example-test-only"


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TailscaleTests(unittest.TestCase):
    def setUp(self):
        self.snapshot_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.snapshot_directory.cleanup)
        snapshot = patch.object(tailscale.tailscale_state, "SNAPSHOT_PATH", Path(self.snapshot_directory.name) / "missing.enc")
        snapshot.start()
        self.addCleanup(snapshot.stop)

    def test_opt_in_settings_validate_and_detect_key_changes(self):
        self.assertIsNone(tailscale.settings_from_env(UUID, {}))
        settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
        self.assertTrue(settings["ephemeral"])
        self.assertTrue(settings["advertise_exit_node"])
        self.assertTrue(settings["advertise_connector"])
        tagged = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_ADVERTISE_TAGS": "tag:app-connector,tag:app-connector"})
        self.assertEqual(tagged["advertise_tags"], ["tag:app-connector"])
        with self.assertRaises(ValueError):
            tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_ADVERTISE_TAGS": "invalid"})
        self.assertEqual(settings["hostname"], "agsb-123e4567")
        self.assertNotIn(KEY, json.dumps(settings))
        changed = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY + "-new"})
        self.assertNotEqual(settings, changed)
        with self.assertRaises(ValueError):
            tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_HOSTNAME": "../bad"})
        with self.assertRaises(ValueError):
            tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_EPHEMERAL": "invalid"})

    def test_generated_config_has_no_embedded_tailscale_and_tracks_port(self):
        installer = load_script("installer_tailscale", "agsb-v2.py")
        settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
        with tempfile.TemporaryDirectory() as directory:
            installer.INSTALL_DIR = Path(directory)
            installer.DEBUG_LOG = Path(directory) / "debug.log"
            for port in (19999, 21111):
                with patch.object(tailscale, "validate_config"):
                    installer.create_sing_box_config(port, UUID, tailscale=settings,
                        cloudflare=tailscale.cloudflare_settings("test-token"))
                config = json.loads((Path(directory) / "sb.json").read_text())
                self.assertNotIn("endpoints", config)
                self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
                self.assertEqual(config["inbounds"][0]["listen_port"], port)
                self.assertEqual(config["route"]["rules"], [{
                    "inbound": [tailscale.CLOUDFLARE_TAG], "action": "route", "outbound": "direct",
                }])
                self.assertNotIn(KEY, json.dumps(config))

    def test_legacy_endpoint_requires_regeneration(self):
        with self.assertRaisesRegex(ValueError, "regenerated"):
            tailscale.runtime_config({"endpoints": [{"type": "tailscale"}]}, {})

    def test_ssh_port_conflict_does_not_replace_existing_configuration(self):
        installer = load_script("installer_tailscale_port_conflict", "agsb-v2.py")
        with tempfile.TemporaryDirectory() as directory:
            installer.INSTALL_DIR = Path(directory)
            installer.DEBUG_LOG = Path(directory) / "debug.log"
            installer.create_sing_box_config(19999, UUID)
            original = (Path(directory) / "sb.json").read_text()
            settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
            with self.assertRaisesRegex(ValueError, "conflicts with Tailscale SSH"):
                installer.create_sing_box_config(22, UUID, tailscale=settings)
            self.assertEqual((Path(directory) / "sb.json").read_text(), original)

    def test_standalone_launcher_install_and_disable(self):
        installer = load_script("installer_launcher", "agsb-v2.py")
        with tempfile.TemporaryDirectory(prefix="agsb test ") as directory:
            root = Path(directory)
            installer.INSTALL_DIR = root
            installer.CONFIG_FILE = root / "config.json"
            installer.TUNNEL_TOKEN_FILE = root / "tunnel_token"
            installer.DEBUG_LOG = root / "debug.log"
            settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
            config = {"port_vm_ws": 19999, "tailscale": settings}
            installer.CONFIG_FILE.write_text(json.dumps(config))
            installer.create_startup_script()
            for name in ("start_sb.sh", "start_tailscale.sh"):
                script = root / name
                self.assertNotIn(KEY, script.read_text())
                self.assertEqual(subprocess.run(["bash", "-n", str(script)]).returncode, 0)
            for name in ("tailscale_daemon.py", "tailscale_support.py", "tailscale_state.py"):
                self.assertTrue((root / name).is_file())
            self.assertIn("tailscale.log", (root / "start_tailscale.sh").read_text())
            config["tailscale"] = None
            installer.CONFIG_FILE.write_text(json.dumps(config))
            installer.create_startup_script()
            self.assertFalse((root / "start_tailscale.sh").exists())

    def test_running_proxy_is_reconfigured_for_enable_change_and_disable(self):
        launcher = load_script("launcher_tailscale", "upload-yuancheng.py")
        settings = {"uuid": UUID, "port": 19999, "agk": "test-token", "domain": "example.test"}
        with tempfile.TemporaryDirectory() as directory:
            launcher.USER_HOME = Path(directory)
            state = Path(directory) / ".agsb"
            state.mkdir()
            config = {
                "uuid_str": UUID, "port_vm_ws": 19999, "custom_domain_agn": "example.test",
                "cloudflare": tailscale.cloudflare_settings(settings["agk"]),
            }
            for filename in ("sbpid.log", "tailscaled.pid", "tailscale-launcher.pid"):
                (state / filename).write_text("12345")
            with patch.object(launcher, "_is_running", return_value=True):
                with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True):
                    (state / "config.json").write_text(json.dumps(config))
                    self.assertFalse(launcher._installer_already_started(settings))
                    config["tailscale"] = tailscale.settings_from_env(UUID)
                    for field in ("implementation", "advertise_connector", "advertise_exit_node"):
                        value = config["tailscale"].pop(field)
                        (state / "config.json").write_text(json.dumps(config))
                        self.assertFalse(launcher._installer_already_started(settings))
                        config["tailscale"][field] = value
                    (state / "config.json").write_text(json.dumps(config))
                    self.assertFalse(launcher._installer_already_started(settings))
                    (state / "tailscale-ready.json").write_text(json.dumps({"settings": config["tailscale"], "port": 19999}))
                    self.assertTrue(launcher._installer_already_started(settings))
                    with patch.dict(os.environ, {"TAILSCALE_HOSTNAME": "other-host"}):
                        self.assertFalse(launcher._installer_already_started(settings))
                    with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY + "-new"}):
                        self.assertFalse(launcher._installer_already_started(settings))
                with patch.dict(os.environ, {}, clear=True):
                    self.assertFalse(launcher._installer_already_started(settings))

    def test_auth_key_is_forwarded_to_installer_only_in_environment(self):
        launcher = load_script("launcher_key", "upload-yuancheng.py")
        with tempfile.TemporaryDirectory() as directory:
            launcher.USER_HOME = Path(directory)
            with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True):
                with patch.object(launcher, "start_log_relay"), patch.object(launcher, "_installer_already_started", return_value=False):
                    with patch.object(launcher.subprocess, "Popen") as popen:
                        popen.return_value.pid = 12345
                        launcher.launch_installer({"uuid": UUID, "port": 19999, "agk": "test-token", "domain": "example.test"})
                        self.assertEqual(popen.call_args.kwargs["env"]["TAILSCALE_AUTH_KEY"], KEY)
                        self.assertEqual(popen.call_args.kwargs["env"]["PYTHONUNBUFFERED"], "1")
                        self.assertNotIn(KEY, str(popen.call_args.args))
            for path in (Path(directory) / ".agsb").iterdir():
                self.assertNotIn(KEY, path.read_text())

    def test_log_relay_redacts_and_handles_partial_lines_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            installer_log = state / "launcher.log"
            sb_log = state / "tailscale.log"
            installer_log.write_text("Tailscale: old message\n")
            sb_log.write_text("")
            relay = tailscale._LogRelay(state, installer_log)
            captured = io.StringIO()
            with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True), contextlib.redirect_stdout(captured):
                with installer_log.open("a") as stream:
                    stream.write("Tailscale: configuring\n")
                sb_log.write_text("DEBUG tailscaled: auth " + KEY)
                relay.poll()
                self.assertNotIn("auth", captured.getvalue())
                with sb_log.open("a") as stream:
                    stream.write("\nordinary proxy line\n")
                relay.poll()
                relay.poll()
                sb_log.write_text("Tailscale SSH connection: ssh appuser@agsb-test\n")
                (state / "tailscale-launcher.pid").write_text("12345")
                relay.poll()
            output = captured.getvalue()
            self.assertIn("configuring", output)
            self.assertIn("ssh appuser@agsb-test", output)
            self.assertEqual(output.count("[redacted]"), 1)
            self.assertNotIn(KEY, output)
            self.assertIn("ordinary proxy", output)
            self.assertNotIn("old message", output)

    def test_service_replacement_stops_only_installation_owned_binary(self):
        installer = load_script("installer_replace", "agsb-v2.py")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            binary = state / "sing-box"
            shutil.copyfile(shutil.which("sleep"), binary)
            binary.chmod(0o755)
            pid_file = state / "sbpid.log"
            process = subprocess.Popen(["sleep", "30"], executable=str(binary))
            try:
                pid_file.write_text(str(process.pid))
                for _ in range(50):
                    if Path(f"/proc/{process.pid}/exe").resolve() == binary:
                        break
                    time.sleep(0.01)
                # Reproduce an atomic binary upgrade while the old inode runs.
                replacement = state / "replacement"
                shutil.copyfile(binary, replacement)
                replacement.chmod(0o755)
                replacement.replace(binary)
                self.assertIsNone(process.poll())
                installer.stop_managed_service(pid_file, binary)
                process.wait(timeout=3)
                self.assertNotEqual(process.returncode, 0)
                pid_file.write_text(str(os.getpid()))
                with patch.object(installer.os, "kill") as kill:
                    installer.stop_managed_service(pid_file, binary)
                    installer.stop_managed_service(pid_file, Path(sys.executable), state / "unrelated.py")
                    kill.assert_not_called()
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)

    def test_log_thread_is_reused_when_streamlit_reruns_or_uuid_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            with patch.dict(tailscale._RELAYS, {}, clear=True), patch.object(tailscale.threading, "Thread") as thread:
                tailscale.start_log_relay(state, state / "first.log")
                tailscale.start_log_relay(state, state / "first.log")
                tailscale.start_log_relay(state, state / "second.log")
                self.assertEqual(thread.call_count, 1)
                relay = tailscale._RELAYS[str(state.resolve())]
                self.assertEqual(relay.paths[0], state / "second.log")
                (state / "second.log").write_text("Tailscale: configuration failed\n")
                with contextlib.redirect_stdout(io.StringIO()) as captured:
                    relay.poll()
                self.assertIn("configuration failed", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
