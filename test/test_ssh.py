import unittest

from pyrage import ssh, RecipientError

from .utils import ssh_keypair


class TestIdentity(unittest.TestCase):
    def test_from_buffer(self):
        for filename in ["ed25519", "rsa4096", "rsa2048"]:
            _pubkey, privkey = ssh_keypair(filename)
            identity = ssh.Identity.from_buffer(privkey.encode())
            self.assertIsInstance(identity, ssh.Identity)


class TestRecipient(unittest.TestCase):
    def test_from_str(self):
        for filename in ["ed25519", "rsa4096", "rsa2048"]:
            pubkey, _privkey = ssh_keypair(filename)
            recipient = ssh.Recipient.from_str(pubkey)
            self.assertIsInstance(recipient, ssh.Recipient)

    def test_from_str_invalid(self):
        with self.assertRaisesRegex(RecipientError, "invalid SSH recipient"):
            ssh.Recipient.from_str("invalid ssh pubkey")
