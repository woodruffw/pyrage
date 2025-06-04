import os
import tempfile
import unittest
from io import BytesIO

from parameterized import parameterized

import pyrage

from .utils import ssh_keypair


class TestPyrage(unittest.TestCase):
    def test_encrypt_fails_with_no_receipients(self):
        with self.assertRaisesRegex(
            pyrage.EncryptError, "expected at least one recipient"
        ):
            pyrage.encrypt(b"test", [])

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        encrypted = pyrage.encrypt(b"test", [recipient], armored=armored)
        decrypted = pyrage.decrypt(encrypted, [identity])

        self.assertEqual(b"test", decrypted)

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip_io_fh(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        with tempfile.TemporaryFile() as unencrypted:
            unencrypted.write(b"test")
            unencrypted.seek(0)
            with tempfile.TemporaryFile() as encrypted:
                pyrage.encrypt_io(unencrypted, encrypted, [recipient], armored=armored)
                encrypted.seek(0)
                with tempfile.TemporaryFile() as decrypted:
                    pyrage.decrypt_io(encrypted, decrypted, [identity])
                    decrypted.seek(0)
                    unencrypted.seek(0)
                    self.assertEqual(unencrypted.read(), decrypted.read())

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip_io_bytesio(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        unencrypted = BytesIO(b"test")
        encrypted = BytesIO()
        decrypted = BytesIO()
        pyrage.encrypt_io(unencrypted, encrypted, [recipient], armored=armored)
        encrypted.seek(0)
        pyrage.decrypt_io(encrypted, decrypted, [identity])
        decrypted.seek(0)
        unencrypted.seek(0)
        self.assertEqual(unencrypted.read(), decrypted.read())

    def test_roundtrip_io_fail(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        with self.assertRaises(TypeError):
            input = "test"
            output = BytesIO()
            pyrage.encrypt_io(input, output, [recipient])

        with self.assertRaises(TypeError):
            input = BytesIO()
            output = "test"
            pyrage.encrypt_io(input, output, [recipient])

        with self.assertRaises(TypeError):
            input = "test"
            output = BytesIO()
            pyrage.decrypt_io(input, output, [recipient])

        with self.assertRaises(TypeError):
            input = BytesIO()
            output = "test"
            pyrage.decrypt_io(input, output, [recipient])

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip_file(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        with tempfile.TemporaryDirectory() as tempdir:
            unencrypted = os.path.join(tempdir, "unencrypted")
            encrypted = os.path.join(tempdir, "encrypted")
            decrypted = os.path.join(tempdir, "decrypted")

            with open(unencrypted, "wb") as file:
                file.write(b"test")

            pyrage.encrypt_file(unencrypted, encrypted, [recipient], armored=armored)
            pyrage.decrypt_file(encrypted, decrypted, [identity])

            with open(unencrypted, "rb") as file1:
                with open(decrypted, "rb") as file2:
                    self.assertEqual(file1.read(), file2.read())

    def test_decrypt_fails_wrong_recipient(self):
        alice = pyrage.x25519.Identity.generate()
        bob = pyrage.x25519.Identity.generate()

        # alice encrypts to herself
        encrypted = pyrage.encrypt(b"test", [alice.to_public()])

        # bob tries to decrypt and fails
        with self.assertRaisesRegex(pyrage.DecryptError, "No matching keys found"):
            pyrage.decrypt(encrypted, [bob])

        # one key matches, so decryption succeeds
        decrypted = pyrage.decrypt(encrypted, [alice, bob])
        self.assertEqual(b"test", decrypted)

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip_matrix(self, armored):
        identities = []
        recipients = []

        age_identity = pyrage.x25519.Identity.generate()
        identities.append(age_identity)
        age_recipient = age_identity.to_public()
        recipients.append(age_recipient)

        for filename in ["ed25519", "rsa4096", "rsa2048"]:
            pubkey, privkey = ssh_keypair(filename)
            identities.append(pyrage.ssh.Identity.from_buffer(privkey.encode()))
            recipients.append(pyrage.ssh.Recipient.from_str(pubkey))

        # Encrypt to all recipients, decode using each identity.
        encrypted = pyrage.encrypt(b"test matrix", recipients, armored=armored)
        for identity in identities:
            self.assertEqual(b"test matrix", pyrage.decrypt(encrypted, [identity]))


if __name__ == "__main__":
    unittest.main()
