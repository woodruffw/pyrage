import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import pyrage

_ASSETS = Path(__file__).parent / "assets"

# Bech32 encodings for the fake `test` plugin; the payload is arbitrary.
_TEST_RECIPIENT = "age1test1qypqxpqhuqytu"
_TEST_IDENTITY = "AGE-PLUGIN-TEST-1PG9SCRG4YANY9"


class Callbacks:
    def __init__(self):
        self.messages = []

    def display_message(self, message):
        self.messages.append(message)

    def confirm(self, message, yes_string, no_string):
        return True

    def request_public_string(self, description):
        return None

    def request_passphrase(self, description):
        return None


class TestIdentity(unittest.TestCase):
    def test_invalid_identity(self):
        with self.assertRaisesRegex(pyrage.IdentityError, "invalid Bech32 encoding"):
            pyrage.plugin.Identity.from_str("invalid~~~")

    def test_invalid_plugin_name(self):
        with self.assertRaisesRegex(pyrage.IdentityError, "Invalid plugin name"):
            pyrage.plugin.Identity.default_for_plugin("invalid~~~name")


@unittest.skipIf(sys.platform == "win32", "plugin shim needs a POSIX shell")
class TestPluginRoundtrip(unittest.TestCase):
    """
    Drives a real (fake) plugin binary through encrypt/decrypt. This covers the
    plugin callbacks being invoked from a thread that has released the GIL.
    """

    def setUp(self):
        # Put an `age-plugin-test` shim on PATH that runs our Python plugin
        # with the current interpreter.
        self._tempdir = tempfile.TemporaryDirectory()
        shim = Path(self._tempdir.name) / "age-plugin-test"
        shim.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{_ASSETS / "age_plugin_test.py"}" "$@"\n'
        )
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)

        self._old_path = os.environ["PATH"]
        os.environ["PATH"] = self._tempdir.name + os.pathsep + self._old_path

    def tearDown(self):
        os.environ["PATH"] = self._old_path
        self._tempdir.cleanup()

    def _recipient(self, callbacks):
        return pyrage.plugin.RecipientPluginV1(
            "test",
            [pyrage.plugin.Recipient.from_str(_TEST_RECIPIENT)],
            [],
            callbacks,
        )

    def _identity(self, callbacks):
        return pyrage.plugin.IdentityPluginV1(
            "test", [pyrage.plugin.Identity.from_str(_TEST_IDENTITY)], callbacks
        )

    def test_roundtrip(self):
        callbacks = Callbacks()

        encrypted = pyrage.encrypt(b"test", [self._recipient(callbacks)])
        decrypted = pyrage.decrypt(encrypted, [self._identity(callbacks)])

        self.assertEqual(b"test", decrypted)
        self.assertEqual(
            ["hello from recipient-v1", "hello from identity-v1"], callbacks.messages
        )

    def test_roundtrip_io(self):
        callbacks = Callbacks()
        with tempfile.TemporaryFile() as plaintext, tempfile.TemporaryFile() as encrypted:
            plaintext.write(b"test")
            plaintext.seek(0)
            pyrage.encrypt_io(plaintext, encrypted, [self._recipient(callbacks)])
            encrypted.seek(0)

            with tempfile.TemporaryFile() as decrypted:
                pyrage.decrypt_io(encrypted, decrypted, [self._identity(callbacks)])
                decrypted.seek(0)
                self.assertEqual(b"test", decrypted.read())

        self.assertEqual(2, len(callbacks.messages))


if __name__ == "__main__":
    unittest.main()
