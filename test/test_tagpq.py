import unittest

from pyrage import RecipientError, tagpq

from test.utils import TAGPQ_RECIPIENT


class TestRecipient(unittest.TestCase):
    def test_from_str(self):
        recipient = tagpq.Recipient.from_str(TAGPQ_RECIPIENT)
        self.assertIsInstance(recipient, tagpq.Recipient)
        self.assertEqual(str(recipient), TAGPQ_RECIPIENT)

    def test_from_str_invalid(self):
        with self.assertRaisesRegex(RecipientError, "invalid Bech32 encoding"):
            tagpq.Recipient.from_str("badprefix")


if __name__ == "__main__":
    unittest.main()
