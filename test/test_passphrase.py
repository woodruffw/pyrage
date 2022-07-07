import unittest

from pyrage import passphrase


class TestPassphrase(unittest.TestCase):
    def test_roundtrip(self):
        plaintext = b"junk"
        encrypted = passphrase.encrypt(plaintext, "some password")
        decrypted = passphrase.decrypt(encrypted, "some password")

        self.assertEqual(plaintext, decrypted)
