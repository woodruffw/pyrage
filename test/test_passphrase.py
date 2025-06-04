import unittest

from parameterized import parameterized

from pyrage import passphrase


class TestPassphrase(unittest.TestCase):
    @parameterized.expand([(False,), (True,)])
    def test_roundtrip(self, armored):
        plaintext = b"junk"
        encrypted = passphrase.encrypt(plaintext, "some password", armored=armored)
        decrypted = passphrase.decrypt(encrypted, "some password")

        self.assertEqual(plaintext, decrypted)
