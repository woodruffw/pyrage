import re
import unittest

from parameterized import parameterized

import pyrage
from pyrage import passphrase


def _work_factor(encrypted):
    match = re.search(rb"-> scrypt \S+ (\d+)", encrypted)
    assert match is not None
    return int(match.group(1))


class TestPassphrase(unittest.TestCase):
    @parameterized.expand([(False,), (True,)])
    def test_roundtrip(self, armored):
        plaintext = b"junk"
        encrypted = passphrase.encrypt(plaintext, "some password", armored=armored)
        decrypted = passphrase.decrypt(encrypted, "some password")

        self.assertEqual(plaintext, decrypted)

    def test_max_work_factor(self):
        encrypted = passphrase.encrypt(b"junk", "some password")
        work_factor = _work_factor(encrypted)

        # A cap at the file's own work factor is enough...
        decrypted = passphrase.decrypt(
            encrypted, "some password", max_work_factor=work_factor
        )
        self.assertEqual(b"junk", decrypted)

        # ...and anything below it is rejected before doing the work.
        with self.assertRaisesRegex(pyrage.DecryptError, "Excessive work"):
            passphrase.decrypt(
                encrypted, "some password", max_work_factor=work_factor - 1
            )

    def test_default_rejects_excessive_work(self):
        encrypted = passphrase.encrypt(b"junk", "some password")
        # Claim a work factor (2 TiB of memory) far beyond age's default cap.
        excessive = re.sub(rb"(-> scrypt \S+) \d+", rb"\1 31", encrypted)

        with self.assertRaisesRegex(pyrage.DecryptError, "Excessive work"):
            passphrase.decrypt(excessive, "some password")

    def test_max_work_factor_type(self):
        encrypted = passphrase.encrypt(b"junk", "some password")
        for bad in (-1, 256, "22"):
            with self.assertRaises((TypeError, OverflowError)):
                passphrase.decrypt(encrypted, "some password", max_work_factor=bad)  # ty: ignore[invalid-argument-type]
