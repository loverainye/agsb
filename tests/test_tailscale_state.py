import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tailscale_state as state
import tailscale_support as support


KEY = base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")
OTHER_KEY = base64.urlsafe_b64encode(b"b" * 32).decode().rstrip("=")


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.identity = json.dumps({"_machinekey": "private-machine-test", "profile-test": "node-key-test"}).encode()
        (self.source / "tailscaled.state").write_bytes(self.identity)
        (self.source / "ssh_host_ed25519_key").write_text("private-ssh-test")
        (self.source / "tailscaled.log1.txt").write_text("exclude log")
        (self.source / "taildrop").mkdir()
        (self.source / "taildrop" / "private.txt").write_text("exclude taildrop")
        self.document = state.collect_state(self.source, "streamlit-agsb")
        self.snapshot = self.root / "tailscale-state.enc"
        self.snapshot.write_bytes(state.encrypt(self.document, KEY))
        self.addCleanup(patch.stopall)
        patch.object(state, "SNAPSHOT_PATH", self.snapshot).start()

    def test_encryption_roundtrip_nonce_and_authentication(self):
        blob = self.snapshot.read_bytes()
        self.assertNotIn(b"private-machine-test", blob)
        self.assertNotEqual(blob, state.encrypt(self.document, KEY))
        self.assertEqual(state.decrypt(blob, KEY), self.document)
        for invalid in (OTHER_KEY, "invalid"):
            with self.assertRaises(ValueError):
                state.decrypt(blob, invalid)
        damaged = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            state.decrypt(damaged, KEY)
        with self.assertRaises(ValueError):
            state.decrypt(b"unknown format", KEY)

    def test_restore_permissions_and_redeploy_keep_identity(self):
        target = self.root / "node"
        env = {state.KEY_ENV: KEY}
        for _ in range(2):
            self.assertTrue(state.restore_state(target, env))
            self.assertEqual((target / "tailscaled.state").read_bytes(), self.identity)
            self.assertEqual((target / "ssh_host_ed25519_key").read_text(), "private-ssh-test")
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            for file in target.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertFalse((target / "taildrop").exists())
            self.assertFalse((target / "tailscaled.log1.txt").exists())
            shutil.rmtree(target)

    def test_newer_local_identity_is_preserved_and_conflicts_stop(self):
        target = self.root / "node"
        env = {state.KEY_ENV: KEY}
        state.restore_state(target, env)
        updated = json.loads(self.identity)
        updated["profile-test"] = "rotated-node-key-test"
        identity = target / "tailscaled.state"
        identity.write_text(json.dumps(updated))
        self.assertFalse(state.restore_state(target, env))
        self.assertEqual(json.loads(identity.read_text()), updated)
        updated["_machinekey"] = "another-machine"
        identity.write_text(json.dumps(updated))
        with self.assertRaisesRegex(ValueError, "differs"):
            state.restore_state(target, env)
        self.assertEqual(json.loads(identity.read_text()), updated)

    def test_bad_key_and_unsafe_paths_do_not_restore(self):
        target = self.root / "node"
        with self.assertRaises(ValueError):
            state.restore_state(target, {state.KEY_ENV: OTHER_KEY})
        self.assertFalse(target.exists())
        self.document["files"]["../escape"] = base64.b64encode(b"escape").decode()
        with self.assertRaisesRegex(ValueError, "invalid identity"):
            state.encrypt(self.document, KEY)
        target.mkdir()
        outside = self.root / "outside"
        outside.write_text("untouched")
        (target / "tailscaled.state").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            state.restore_state(target, {state.KEY_ENV: KEY})
        self.assertEqual(outside.read_text(), "untouched")

    def test_official_ssh_directory_roundtrip_and_symlink_rejection(self):
        ssh_dir = self.source / "ssh"
        ssh_dir.mkdir()
        (ssh_dir / "ssh_host_ed25519_key").write_text("newer-private-ssh-test")
        (ssh_dir / "unrelated-file").write_text("exclude")
        document = state.collect_state(self.source, "streamlit-agsb")
        self.assertIn("ssh/ssh_host_ed25519_key", document["files"])
        self.assertNotIn("ssh/unrelated-file", document["files"])
        self.snapshot.write_bytes(state.encrypt(document, KEY))
        target = self.root / "official-node"
        state.restore_state(target, {state.KEY_ENV: KEY})
        key = target / "ssh" / "ssh_host_ed25519_key"
        self.assertEqual(key.read_text(), "newer-private-ssh-test")
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.parent.stat().st_mode & 0o777, 0o700)
        unsafe = self.root / "unsafe-node"
        unsafe.mkdir()
        (unsafe / "ssh").symlink_to(ssh_dir)
        with self.assertRaisesRegex(ValueError, "unsafe SSH"):
            state.restore_state(unsafe, {state.KEY_ENV: KEY})
        with self.assertRaisesRegex(ValueError, "unsafe SSH"):
            state.collect_state(unsafe, "streamlit-agsb")

    def test_settings_enable_with_snapshot_only_and_fail_closed(self):
        env = {state.KEY_ENV: KEY}
        settings = support.settings_from_env("new-random-uuid", env)
        self.assertEqual(settings["hostname"], "streamlit-agsb")
        self.assertFalse(settings["ephemeral"])
        self.assertIn("state_snapshot", settings)
        self.assertNotIn(KEY, json.dumps(settings))
        for extra in ({"TAILSCALE_EPHEMERAL": "true"}, {state.KEY_ENV: OTHER_KEY}):
            with self.assertRaises(ValueError):
                support.settings_from_env("uuid", {**env, **extra})
        with self.assertRaisesRegex(ValueError, "TAILSCALE_STATE_KEY"):
            support.settings_from_env("uuid", {"TAILSCALE_AUTH_KEY": "bootstrap-key"})
        with patch.dict(os.environ, env, clear=True):
            self.assertNotIn(state.KEY_ENV, support.singbox_environment())
            self.assertEqual(support.redact(KEY), "[redacted]")

    def test_installed_daemon_restores_legacy_identity_without_key_in_child(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("snapshot_installer", Path(__file__).resolve().parents[1] / "agsb-v2.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        installed = self.root / "installed"
        installed.mkdir()
        installer.INSTALL_DIR = installed
        installer.CONFIG_FILE = installed / "config.json"
        installer.SB_PID_FILE = installed / "sbpid.log"
        installer.TUNNEL_TOKEN_FILE = installed / "tunnel_token"
        installer.DEBUG_LOG = installed / "debug.log"
        env = {state.KEY_ENV: KEY}
        settings = support.settings_from_env("uuid", env)
        installer.CONFIG_FILE.write_text(json.dumps({"port_vm_ws": 19999, "tailscale": settings}))
        installer.create_startup_script()
        self.assertEqual((installed / "tailscale-state.enc").read_bytes(), self.snapshot.read_bytes())
        # Exercise the installed daemon's restore function with the synthetic
        # encrypted identity; never enroll or run the repository's real node.
        process = subprocess.run(
            [sys.executable, "-c",
             "import json,os; from pathlib import Path; import tailscale_daemon as d; "
             "settings=json.loads(Path('config.json').read_text())['tailscale']; "
             "directory=d.prepare_state(Path.cwd(),settings); "
             "print(json.dumps({'identity':(directory/'tailscaled.state').read_text(),"
             "'key_in_child': 'TAILSCALE_STATE_KEY' in d.singbox_environment()}))"],
            cwd=installed, capture_output=True, text=True, env={**os.environ, **env}, timeout=10,
        )
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        reported = json.loads(process.stdout.splitlines()[-1])
        self.assertEqual(json.loads(reported["identity"]), json.loads(self.identity))
        hostkey = installed / "tailscale" / "ssh" / "ssh_host_ed25519_key"
        self.assertEqual(hostkey.read_text(), "private-ssh-test")
        self.assertEqual(hostkey.stat().st_mode & 0o777, 0o600)
        self.assertFalse(reported["key_in_child"])
        self.assertNotIn(KEY, process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
