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
    def test_opt_in_settings_validate_and_detect_key_changes(self):
        self.assertIsNone(tailscale.settings_from_env(UUID, {}))
        settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
        self.assertTrue(settings["ephemeral"])
        self.assertEqual(settings["hostname"], "agsb-123e4567")
        self.assertNotIn(KEY, json.dumps(settings))
        changed = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY + "-new"})
        self.assertNotEqual(settings, changed)
        with self.assertRaises(ValueError):
            tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_HOSTNAME": "../bad"})
        with self.assertRaises(ValueError):
            tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY, "TAILSCALE_EPHEMERAL": "invalid"})

    def test_generated_config_preserves_vmess_and_excludes_key(self):
        installer = load_script("installer_tailscale", "agsb-v2.py")
        with tempfile.TemporaryDirectory() as directory:
            installer.INSTALL_DIR = Path(directory)
            installer.DEBUG_LOG = Path(directory) / "debug.log"
            installer.create_sing_box_config(19999, UUID)
            vanilla = json.loads((Path(directory) / "sb.json").read_text())
            self.assertNotIn("endpoints", vanilla)
            settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
            with patch.object(tailscale, "validate_config") as validate:
                installer.create_sing_box_config(19999, UUID, tailscale=settings)
                validate.assert_called_once()
            config = json.loads((Path(directory) / "sb.json").read_text())
            self.assertEqual(config["inbounds"], vanilla["inbounds"])
            self.assertEqual(config["outbounds"], vanilla["outbounds"])
            self.assertEqual(config["route"]["final"], "direct")
            self.assertTrue(config["endpoints"][0]["ssh_server"])
            self.assertFalse(config["endpoints"][0]["system_interface"])
            self.assertNotIn(KEY, json.dumps(config))
            self.assertEqual((Path(directory) / "tailscale").stat().st_mode & 0o777, 0o700)
            runtime = json.loads(tailscale.runtime_config(config, {"TAILSCALE_AUTH_KEY": KEY}))
            self.assertEqual(runtime["endpoints"][0]["auth_key"], KEY)
            self.assertNotIn("auth_key", config["endpoints"][0])
            with self.assertRaises(ValueError):
                tailscale.runtime_config(config, {})

    def test_preflight_uses_stdin_and_redacts_validation_errors(self):
        config = {"endpoints": [{"tag": tailscale.TAILSCALE_TAG}]}
        binary = Path("/tmp/test-sing-box")
        version = subprocess.CompletedProcess([], 0, "sing-box version 1.14.3\nTags: with_tailscale\n", "")
        checked = subprocess.CompletedProcess([], 1, "", "invalid auth " + KEY)
        with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True):
            with patch.object(tailscale.subprocess, "run", side_effect=[version, checked]) as run:
                with self.assertRaises(RuntimeError) as error:
                    tailscale.validate_config(binary, config)
                self.assertNotIn(KEY, str(error.exception))
                self.assertEqual(json.loads(run.call_args.kwargs["input"])["endpoints"][0]["auth_key"], KEY)
                self.assertNotIn(KEY, str(run.call_args.args))
        for output in ("sing-box version 1.13.0\nTags: with_tailscale", "sing-box version 1.14.3\nTags: with_gvisor"):
            with patch.object(tailscale.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
                with self.assertRaises(RuntimeError):
                    tailscale.validate_config(binary, config)
                self.assertEqual(run.call_count, 1)

    def test_startup_exec_keeps_pid_and_credentials_stay_in_stdin(self):
        installer = load_script("installer_exec", "agsb-v2.py")
        with tempfile.TemporaryDirectory(prefix="agsb test ") as directory:
            state = Path(directory)
            installer.INSTALL_DIR = state
            installer.CONFIG_FILE = state / "config.json"
            installer.SB_PID_FILE = state / "sbpid.log"
            installer.ARGO_PID_FILE = state / "sbargopid.log"
            installer.TUNNEL_TOKEN_FILE = state / "tunnel_token"
            installer.DEBUG_LOG = state / "debug.log"
            installer.LOG_FILE = state / "argo.log"
            settings = tailscale.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
            config = {"log": {"level": "info"}}
            tailscale.add_endpoint(config, settings, state)
            template = json.dumps(config)
            (state / "sb.json").write_text(template)
            installer.CONFIG_FILE.write_text(json.dumps({"port_vm_ws": 19999, "tailscale": settings}))
            installer.create_startup_script()
            script = (state / "start_sb.sh").read_text()
            self.assertNotIn(KEY, script)
            self.assertEqual(subprocess.run(["bash", "-n", str(state / "start_sb.sh")]).returncode, 0)
            # A substitute executable reports its input and PID, without a tailnet login.
            binary = state / "sing-box"
            binary.write_text(f"#!{sys.executable}\nimport os,sys,json\nprint(json.dumps({{'pid':os.getpid(),'args':sys.argv[1:],'key_env':os.getenv('TAILSCALE_AUTH_KEY'),'config':json.load(sys.stdin)}}))\n")
            binary.chmod(0o755)
            env = os.environ.copy()
            env["TAILSCALE_AUTH_KEY"] = KEY
            process = subprocess.Popen(
                [sys.executable, str(state / "tailscale_support.py"), directory],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            reported = json.loads(stdout.splitlines()[-1])
            self.assertEqual(reported["pid"], process.pid)
            self.assertEqual(reported["args"], ["run", "-c", "stdin"])
            self.assertIsNone(reported["key_env"])
            self.assertEqual(reported["config"]["endpoints"][0]["auth_key"], KEY)
            self.assertEqual((state / "sb.json").read_text(), template)
            self.assertIn("Tailscale SSH connection: ssh", stdout)
            self.assertNotIn(KEY, "\n".join(stdout.splitlines()[:-1]))

    def test_running_proxy_is_reconfigured_for_enable_change_and_disable(self):
        launcher = load_script("launcher_tailscale", "upload-yuancheng.py")
        settings = {"uuid": UUID, "port": 19999, "agk": "test-token", "domain": "example.test"}
        with tempfile.TemporaryDirectory() as directory:
            launcher.USER_HOME = Path(directory)
            state = Path(directory) / ".agsb"
            state.mkdir()
            config = {"uuid_str": UUID, "port_vm_ws": 19999, "custom_domain_agn": "example.test"}
            for filename in ("sbpid.log", "sbargopid.log"):
                (state / filename).write_text("12345")
            with patch.object(launcher, "_is_running", return_value=True):
                with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True):
                    (state / "config.json").write_text(json.dumps(config))
                    self.assertFalse(launcher._installer_already_started(settings))
                    config["tailscale"] = tailscale.settings_from_env(UUID)
                    (state / "config.json").write_text(json.dumps(config))
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
            sb_log = state / "sb.log"
            installer_log.write_text("Tailscale: old message\n")
            sb_log.write_text("")
            relay = tailscale._LogRelay(state, installer_log)
            captured = io.StringIO()
            with patch.dict(os.environ, {"TAILSCALE_AUTH_KEY": KEY}, clear=True), contextlib.redirect_stdout(captured):
                with installer_log.open("a") as stream:
                    stream.write("Tailscale: configuring\n")
                sb_log.write_text("DEBUG endpoint/tailscale[tailscale-ssh]: auth " + KEY)
                relay.poll()
                self.assertNotIn("auth", captured.getvalue())
                with sb_log.open("a") as stream:
                    stream.write("\nordinary proxy line\n")
                relay.poll()
                relay.poll()
                sb_log.write_text("Tailscale SSH connection: ssh appuser@agsb-test\n")
                (state / "sbpid.log").write_text("12345")
                relay.poll()
            output = captured.getvalue()
            self.assertIn("configuring", output)
            self.assertIn("ssh appuser@agsb-test", output)
            self.assertEqual(output.count("[redacted]"), 1)
            self.assertNotIn(KEY, output)
            self.assertNotIn("ordinary proxy", output)
            self.assertNotIn("old message", output)

    def test_service_replacement_stops_only_installation_owned_binary(self):
        installer = load_script("installer_replace", "agsb-v2.py")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            binary = state / "sing-box"
            shutil.copyfile(sys.executable, binary)
            binary.chmod(0o755)
            pid_file = state / "sbpid.log"
            process = subprocess.Popen([str(binary), "-c", "import time; time.sleep(30)"])
            try:
                pid_file.write_text(str(process.pid))
                for _ in range(50):
                    if Path(f"/proc/{process.pid}/exe").resolve() == binary:
                        break
                    time.sleep(0.01)
                installer.stop_managed_service(pid_file, binary)
                process.wait(timeout=3)
                self.assertNotEqual(process.returncode, 0)
                pid_file.write_text(str(os.getpid()))
                with patch.object(installer.os, "kill") as kill:
                    installer.stop_managed_service(pid_file, binary)
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
