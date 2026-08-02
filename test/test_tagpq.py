import unittest

from pyrage import RecipientError, tagpq

from test.utils import age_recipient


class TestRecipient(unittest.TestCase):
    def test_from_str(self):
        recipient = tagpq.Recipient.from_str(age_recipient("tagpq"))
        self.assertIsInstance(recipient, tagpq.Recipient)
        self.assertEqual(str(recipient), age_recipient("tagpq"))

    def test_from_str_invalid(self):
        with self.assertRaisesRegex(RecipientError, "invalid Bech32 encoding"):
            tagpq.Recipient.from_str("badprefix")


if __name__ == "__main__":
    unittest.main()
