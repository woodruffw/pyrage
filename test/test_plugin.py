import unittest

import pyrage


class TestIdentity(unittest.TestCase):
    def test_invalid_identity(self):
        with self.assertRaisesRegex(pyrage.IdentityError, "invalid Bech32 encoding"):
            pyrage.plugin.Identity.from_str("invalid~~~")

    def test_invalid_plugin_name(self):
        with self.assertRaisesRegex(pyrage.IdentityError, "Invalid plugin name"):
            pyrage.plugin.Identity.default_for_plugin("invalid~~~name")
