import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tailscale_support as support


ROOT = Path(__file__).resolve().parents[1]
UUID = "123e4567-e89b-12d3-a456-426614174000"
TOKEN = "cloudflare-test-token-private"
KEY = "tskey-auth-test-private"


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def installation():
    installer = load_script("installer_cloudflare", "agsb-v2.py")
    previous_directory = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="agsb cloudflare ") as directory:
        state = Path(directory)
        installer.INSTALL_DIR = state
        for attribute, filename in (
            ("CONFIG_FILE", "config.json"), ("SB_PID_FILE", "sbpid.log"),
            ("ARGO_PID_FILE", "sbargopid.log"), ("GATEWAY_PID_FILE", "gatewaypid.log"),
            ("GATEWAY_SCRIPT_FILE", "gateway.py"), ("TUNNEL_TOKEN_FILE", "tunnel_token"),
            ("DEBUG_LOG", "debug.log"), ("LOG_FILE", "argo.log"),
        ):
            setattr(installer, attribute, state / filename)
        try:
            yield installer, state
        finally:
            os.chdir(previous_directory)


class CloudflareTests(unittest.TestCase):
    def setUp(self):
        self.snapshot_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.snapshot_directory.cleanup)
        snapshot = patch.object(support.tailscale_state, "SNAPSHOT_PATH", Path(self.snapshot_directory.name) / "missing.enc")
        snapshot.start()
        self.addCleanup(snapshot.stop)

    def test_template_injects_token_only_at_runtime_and_composes_with_tailscale(self):
        with installation() as (installer, state):
            settings = support.cloudflare_settings(TOKEN)
            tailscale = support.settings_from_env(UUID, {"TAILSCALE_AUTH_KEY": KEY})
            for endpoint in (None, tailscale):
                with patch.object(support, "validate_config"):
                    installer.create_sing_box_config(19999, UUID, tailscale=endpoint, cloudflare=settings)
                template = json.loads((state / "sb.json").read_text())
                self.assertEqual(template["inbounds"][0]["listen_port"], 19999)
                self.assertEqual(template["inbounds"][1]["type"], "cloudflared")
                self.assertNotIn("token", template["inbounds"][1])
                self.assertEqual(template["route"]["final"], "direct")
                self.assertIn({"inbound": [support.CLOUDFLARE_TAG], "action": "route", "outbound": "direct"}, template["route"]["rules"])
                if endpoint:
                    self.assertIn({"inbound": [support.TAILSCALE_TAG], "action": "reject"}, template["route"]["rules"])
                runtime = json.loads(support.runtime_config(template, {"agk": TOKEN, "TAILSCALE_AUTH_KEY": KEY}))
                self.assertEqual(runtime["inbounds"][1]["token"], TOKEN)
                self.assertNotIn(TOKEN, json.dumps(settings))
                self.assertNotIn(TOKEN, (state / "sb.json").read_text())
                with self.assertRaisesRegex(ValueError, "AGK"):
                    support.runtime_config(template, {"TAILSCALE_AUTH_KEY": KEY})

    def test_version_and_build_tags_are_checked_for_enabled_features(self):
        config = {"inbounds": [{"type": "cloudflared", "tag": support.CLOUDFLARE_TAG}]}
        for version in ("sing-box version 1.13.0\nTags: with_cloudflared", "sing-box version 1.14.3\nTags: with_tailscale"):
            with patch.object(support.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, version, "")) as run:
                with self.assertRaises(RuntimeError):
                    support.validate_config("sing-box", config)
                self.assertEqual(run.call_count, 1)
        version = subprocess.CompletedProcess([], 0, "sing-box version 1.14.3\nTags: with_cloudflared", "")
        error = subprocess.CompletedProcess([], 1, "", "invalid token " + TOKEN)
        with patch.dict(os.environ, {"AGK": TOKEN}, clear=True), patch.object(support.subprocess, "run", side_effect=[version, error]) as run:
            with self.assertRaises(RuntimeError) as raised:
                support.validate_config("sing-box", config)
            self.assertNotIn(TOKEN, str(raised.exception))
            self.assertEqual(json.loads(run.call_args.kwargs["input"])["inbounds"][0]["token"], TOKEN)
            self.assertNotIn(TOKEN, str(run.call_args.args))
            self.assertNotIn("AGK", run.call_args.kwargs["env"])
        config["endpoints"] = [{"tag": support.TAILSCALE_TAG}]
        with patch.object(support.subprocess, "run", return_value=version):
            with self.assertRaisesRegex(RuntimeError, "with_tailscale"):
                support.validate_config("sing-box", config)

    def test_cloudflare_launcher_keeps_pid_and_removes_token_environment_without_tailscale(self):
        with installation() as (installer, state):
            installer.CONFIG_FILE.write_text(json.dumps({"port_vm_ws": 19999, "cloudflare": support.cloudflare_settings(TOKEN)}))
            with patch.object(support, "validate_config"):
                installer.create_sing_box_config(19999, UUID, cloudflare=support.cloudflare_settings(TOKEN))
            template = (state / "sb.json").read_text()
            installer.create_startup_script()
            self.assertFalse((state / "start_cf.sh").exists())
            script = (state / "start_sb.sh").read_text()
            self.assertNotIn(TOKEN, script)
            self.assertEqual(subprocess.run(["bash", "-n", str(state / "start_sb.sh")]).returncode, 0)
            binary = state / "sing-box"
            binary.write_text(f"#!{sys.executable}\nimport os,sys,json\nprint(json.dumps({{'pid':os.getpid(),'args':sys.argv[1:],'env':{{k:os.getenv(k) for k in ['AGK','agk','TAILSCALE_AUTH_KEY']}},'config':json.load(sys.stdin)}}))\n")
            binary.chmod(0o755)
            environment = dict(os.environ, AGK=TOKEN, agk=TOKEN)
            process = subprocess.Popen([sys.executable, str(state / "tailscale_support.py"), str(state)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
            output, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, error)
            report = json.loads(output.splitlines()[-1])
            self.assertEqual(report["pid"], process.pid)
            self.assertEqual(report["args"], ["run", "-c", "stdin"])
            self.assertTrue(all(value is None for value in report["env"].values()))
            self.assertEqual(report["config"]["inbounds"][1]["token"], TOKEN)
            self.assertEqual((state / "sb.json").read_text(), template)
            self.assertIn("Cloudflare: starting Tunnel", output)
            self.assertNotIn(TOKEN, "\n".join(output.splitlines()[:-1]))

    def test_install_migrates_without_cloudflared_download_or_persisted_token(self):
        with installation() as (installer, state), patch.dict(os.environ, {}, clear=True):
            (state / "sing-box").write_text("existing binary")
            (state / "start_cf.sh").write_text("old standalone launcher")
            (state / "tunnel_token").write_text("old-token")
            args = SimpleNamespace(uuid=UUID, vmpt=19999, agk=TOKEN, agn="example.test", ssh_file=None, public_port=None, no_autostart=True, embedded_cloudflare=True)
            with patch.object(installer, "download_binary", side_effect=AssertionError("unexpected cloudflared download")), patch.object(installer, "download_file", side_effect=AssertionError("unexpected download")), patch.object(support, "validate_config"), patch.object(installer, "start_services"), patch.object(installer, "generate_links"), patch.object(installer, "setup_autostart") as autostart:
                installer.install(args)
                autostart.assert_not_called()
            config = json.loads(installer.CONFIG_FILE.read_text())
            self.assertEqual(config["cloudflare"], support.cloudflare_settings(TOKEN))
            self.assertEqual(config["port_vm_ws"], 19999)
            self.assertFalse((state / "start_cf.sh").exists())
            self.assertFalse((state / "tunnel_token").exists())
            for path in state.iterdir():
                if path.is_file():
                    self.assertNotIn(TOKEN, path.read_text())

    def test_startup_waits_for_listener_and_requires_only_singbox_pid(self):
        with installation() as (installer, state):
            installer.CONFIG_FILE.write_text(json.dumps({"port_vm_ws": 19999, "gateway_port": 19999, "cloudflare": support.cloudflare_settings(TOKEN)}))
            installer.SB_PID_FILE.write_text(str(os.getpid()))
            installer.ARGO_PID_FILE.write_text("12345")
            with patch.object(installer, "stop_managed_service") as stop, patch.object(installer.subprocess, "run") as run, patch.object(installer.time, "sleep"), patch.object(installer.socket, "socket") as socket:
                probe = socket.return_value.__enter__.return_value
                probe.connect_ex.side_effect = [111, 0]
                installer.start_services()
                self.assertEqual(probe.connect_ex.call_count, 2)
                self.assertEqual(stop.call_count, 2)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0], ["bash", str(state / "start_sb.sh")])
            self.assertFalse(installer.ARGO_PID_FILE.exists())
            with patch.object(installer, "stop_managed_service"), patch.object(installer.subprocess, "run"), patch.object(installer, "process_running", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "sing-box"):
                    installer.start_services()

    def test_reuse_checks_token_domain_and_embedded_mode_for_running_installer(self):
        launcher = load_script("launcher_cloudflare", "upload-yuancheng.py")
        settings = {"uuid": UUID, "port": 19999, "agk": TOKEN, "domain": "example.test"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            launcher.USER_HOME = Path(directory)
            state = Path(directory) / ".agsb"
            state.mkdir()
            marker = state / f"launcher-{UUID}.pid"
            marker.write_text("12345")
            marker.with_suffix(".runtime.json").write_text(json.dumps({"tailscale": None, "cloudflare": support.cloudflare_settings(TOKEN), "domain": "example.test"}))
            # Build explicit fields so the NUL before a digit is unambiguous.
            arguments = b"\0".join([b"python3", b"agsb-v2.py", b"install", b"--uuid", UUID.encode(), b"--port", b"19999", b"--embedded-cloudflare"])
            with patch.object(Path, "read_bytes", return_value=arguments):
                self.assertTrue(launcher._installer_already_started(settings))
                self.assertFalse(launcher._installer_already_started(dict(settings, agk=TOKEN + "-changed")))
                self.assertFalse(launcher._installer_already_started(dict(settings, domain="other.test")))
            with patch.object(Path, "read_bytes", return_value=arguments.replace(b"--embedded-cloudflare", b"--no-autostart")):
                self.assertFalse(launcher._installer_already_started(settings))

    def test_log_relay_forwards_registration_and_errors_and_redacts_cli_token(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            state = Path(directory)
            relay = support._LogRelay(state, state / "launcher.log", secrets=(TOKEN,))
            (state / "sb.log").write_text(
                "INFO inbound/cloudflared[cloudflare-tunnel]: connected to LAX via quic\n"
                "INFO inbound/cloudflared[cloudflare-tunnel]: updated ingress configuration (version 1)\n"
                "ERROR inbound/cloudflared[cloudflare-tunnel]: register connection: " + TOKEN + "\n"
                "INFO inbound/cloudflared[cloudflare-tunnel]: inbound connection to localhost:19999\n"
                "ordinary proxy line\n"
            )
            (state / "launcher.log").write_text("Cloudflare: still starting\nValueError: missing token\n")
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                relay.poll()
                relay.poll()
            output = captured.getvalue()
            self.assertEqual(output.count("connected to LAX"), 1)
            self.assertIn("updated ingress", output)
            self.assertIn("ValueError", output)
            self.assertIn("[redacted]", output)
            self.assertNotIn(TOKEN, output)
            self.assertNotIn("ordinary proxy", output)
            self.assertNotIn("inbound connection to", output)

    def test_autostart_removes_old_cloudflared_entry(self):
        with installation() as (installer, state):
            (state / "start_sb.sh").write_text("launcher")
            existing = f"@reboot {state / 'start_cf.sh'}\n0 0 * * * unrelated-job\n"
            installed = []
            def capture_crontab(command, **kwargs):
                installed.append(Path(shlex.split(command)[1]).read_text())
            with patch.object(installer.subprocess, "check_output", return_value=existing), patch.object(installer.subprocess, "run", side_effect=capture_crontab):
                installer.setup_autostart()
            self.assertIn("start_sb.sh", installed[0])
            self.assertIn("unrelated-job", installed[0])
            self.assertNotIn("start_cf.sh", installed[0])


if __name__ == "__main__":
    unittest.main()
