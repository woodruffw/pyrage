import unittest

from pyrage import RecipientError, tag

from test.utils import TAG_RECIPIENT


class TestRecipient(unittest.TestCase):
    def test_from_str(self):
        recipient = tag.Recipient.from_str(TAG_RECIPIENT)
        self.assertIsInstance(recipient, tag.Recipient)
        self.assertEqual(str(recipient), TAG_RECIPIENT)

    def test_from_str_invalid(self):
        with self.assertRaisesRegex(RecipientError, "invalid Bech32 encoding"):
            tag.Recipient.from_str("badprefix")


if __name__ == "__main__":
    unittest.main()
