import unittest

import pyrage


class TestPyrage(unittest.TestCase):
    def test_roundtrip(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        encrypted = pyrage.encrypt(b'test', [recipient])
        decrypted = pyrage.decrypt(encrypted, [identity])

        self.assertEqual(b'test', decrypted)


if __name__ == '__main__':
    unittest.main()
