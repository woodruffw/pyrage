import unittest

from pyrage import x25519


class TestIdentity(unittest.TestCase):
    def test_generate(self):
        identity = x25519.Identity.generate()
        self.assertIsInstance(identity, x25519.Identity)
        self.assertTrue(str(identity).startswith("AGE-SECRET-KEY"))

        recipient = identity.to_public()
        self.assertTrue(str(recipient).startswith("age"))

    def test_from_str(self):
        generated = x25519.Identity.generate()
        parsed = x25519.Identity.from_str(str(generated))
        self.assertIsInstance(parsed, x25519.Identity)

    def test_from_str_invalid(self):
        with self.assertRaisesRegex(ValueError, "invalid Bech32 encoding"):
            x25519.Identity.from_str("BAD-PREFIX")


class TestRecipient(unittest.TestCase):
    def test_from_str(self):
        recipient = x25519.Recipient.from_str(
            "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
        )
        self.assertIsInstance(recipient, x25519.Recipient)
        self.assertEqual(
            str(recipient),
            "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj",
        )

    def test_from_str_invalid(self):
        with self.assertRaisesRegex(ValueError, "invalid Bech32 encoding"):
            x25519.Recipient.from_str("badprefix")


if __name__ == "__main__":
    unittest.main()
