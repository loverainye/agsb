import contextlib
import io
import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import upterm_manager as upterm


class UptermTests(unittest.TestCase):
    def test_restore_bundled_executables_and_reuse_without_downloading(self):
        for architecture, (name, digest) in upterm.BUNDLED_BINARIES.items():
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                with patch.dict(os.environ, {}, clear=True), patch.object(upterm.platform, "system", return_value="Linux"), patch.object(upterm.platform, "machine", return_value=architecture), contextlib.redirect_stdout(io.StringIO()):
                    manager = upterm.UptermManager(home=home)
                    self.assertTrue(manager.prepare())
                    self.assertEqual(upterm._file_sha256(manager.path), digest)
                    self.assertEqual(manager.path.stat().st_mode & 0o777, 0o755)
                    self.assertTrue(manager.prepare())
                self.assertEqual(manager.path, home / "upterm")
                self.assertTrue((upterm.BUNDLE_DIR / name).is_file())

    def test_connection_log_contains_plain_ssh_command(self):
        manager = upterm.UptermManager(home="/tmp/upterm-unit-test")
        session = {"status": "ready", "sshCommand": "ssh test-session@uptermd.upterm.dev"}
        with contextlib.redirect_stdout(io.StringIO()) as log:
            self.assertTrue(manager._log_connection(session))
        self.assertIn("Upterm SSH connection: ssh test-session@uptermd.upterm.dev", log.getvalue())

    def test_websocket_connection_is_converted_to_plain_ssh(self):
        manager = upterm.UptermManager(home="/tmp/upterm-unit-test")
        session = {"status": "ready", "sshCommand": "ssh -o 'ProxyCommand=upterm proxy wss://test-session@uptermd.upterm.dev' test-session@uptermd.upterm.dev:443"}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(manager._log_connection(session))
        self.assertEqual(manager.connection_command, "ssh test-session@uptermd.upterm.dev")

    def test_detached_session_starts_and_is_reused_on_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = upterm.UptermManager(home=directory)
            manager.path = Path(directory) / "upterm"
            manager.state_dir.mkdir()
            session = {"status": "ready", "sshCommand": "ssh test-session@uptermd.upterm.dev"}
            response = subprocess.CompletedProcess([], 0, json.dumps(session), "")
            with patch.dict(os.environ, {}, clear=True), patch.object(manager, "_run", return_value=response) as run, contextlib.redirect_stdout(io.StringIO()) as log:
                self.assertTrue(manager.start())
                arguments = run.call_args.args[0]
                self.assertIn("--detach", arguments)
                self.assertIn("--accept", arguments)
                self.assertEqual(arguments[arguments.index("--server") + 1], upterm.SERVER)
                self.assertTrue(manager.start())
                self.assertEqual(run.call_args.args[0][:2], ["session", "info"])
            self.assertTrue(manager.reused_process)
            self.assertEqual(log.getvalue().count("Upterm SSH connection: ssh test-session@uptermd.upterm.dev"), 2)


if __name__ == "__main__":
    unittest.main()
