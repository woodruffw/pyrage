import unittest

import pyrage

from .utils import ssh_keypair


class TestPyrage(unittest.TestCase):
    def test_roundtrip(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        encrypted = pyrage.encrypt(b"test", [recipient])
        decrypted = pyrage.decrypt(encrypted, [identity])

        self.assertEqual(b"test", decrypted)

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

    def test_roundtrip_matrix(self):
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
        encrypted = pyrage.encrypt(b"test matrix", recipients)
        for identity in identities:
            self.assertEqual(b"test matrix", pyrage.decrypt(encrypted, [identity]))


if __name__ == "__main__":
    unittest.main()
