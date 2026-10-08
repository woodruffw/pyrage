import os
import tempfile
import threading
import time
import unittest

import pyrage


class TestReleasesGil(unittest.TestCase):
    def assertReleasesGil(self, fn):
        """
        Runs `fn` on a worker thread while this thread spins. If `fn` held
        the GIL, this thread would stall for its whole duration; with it
        released, we keep getting scheduled.
        """
        done = threading.Event()

        def worker():
            fn()
            done.set()

        # Start the clock before the thread: if `fn` holds the GIL, this
        # thread stalls inside `start()` itself, and that stall must count.
        start = last = time.monotonic()
        max_gap = 0.0
        thread = threading.Thread(target=worker)
        thread.start()
        while not done.is_set():
            now = time.monotonic()
            max_gap = max(max_gap, now - last)
            last = now
        elapsed = time.monotonic() - start
        thread.join()

        self.assertLess(max_gap, elapsed / 2)

    def test_encrypt(self):
        recipient = pyrage.x25519.Identity.generate().to_public()
        plaintext = b"\x00" * (64 * 1024 * 1024)
        self.assertReleasesGil(lambda: pyrage.encrypt(plaintext, [recipient]))

    def test_decrypt(self):
        identity = pyrage.x25519.Identity.generate()
        plaintext = b"\x00" * (64 * 1024 * 1024)
        encrypted = pyrage.encrypt(plaintext, [identity.to_public()])
        self.assertReleasesGil(lambda: pyrage.decrypt(encrypted, [identity]))

    def test_file(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        with tempfile.TemporaryDirectory() as tempdir:
            plaintext = os.path.join(tempdir, "plaintext")
            encrypted = os.path.join(tempdir, "encrypted")
            decrypted = os.path.join(tempdir, "decrypted")
            with open(plaintext, "wb") as file:
                file.write(b"\x00" * (64 * 1024 * 1024))

            self.assertReleasesGil(
                lambda: pyrage.encrypt_file(plaintext, encrypted, [recipient])
            )
            self.assertReleasesGil(
                lambda: pyrage.decrypt_file(encrypted, decrypted, [identity])
            )


if __name__ == "__main__":
    unittest.main()
