import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from io import BytesIO

from parameterized import parameterized

from pyrage import DecryptError, passphrase


class ChunkedReader:
    """File-like that yields plaintext in fixed-size chunks."""

    def __init__(self, data: bytes, chunk_size: int = 3):
        self._data = data
        self._chunk_size = chunk_size
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._data):
            return b""
        if size is None or size < 0:
            size = len(self._data) - self._offset
        size = min(size, self._chunk_size, len(self._data) - self._offset)
        start = self._offset
        self._offset += size
        return self._data[start : self._offset]


class TestPassphrase(unittest.TestCase):
    @parameterized.expand([(False,), (True,)])
    def test_roundtrip(self, armored):
        plaintext = b"junk"
        encrypted = passphrase.encrypt(plaintext, "some password", armored=armored)
        decrypted = passphrase.decrypt(encrypted, "some password")

        self.assertEqual(plaintext, decrypted)

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip_io_bytesio(self, armored):
        plaintext = b"streamed junk"
        encrypted = BytesIO()
        decrypted = BytesIO()
        passphrase.encrypt_io(BytesIO(plaintext), encrypted, "some password", armored=armored)
        encrypted.seek(0)
        passphrase.decrypt_io(encrypted, decrypted, "some password")
        self.assertEqual(plaintext, decrypted.getvalue())

    @parameterized.expand([(False,), (True,)])
    def test_roundtrip_io_chunked(self, armored):
        plaintext = b"abcdefghijklmnopqrstuvwxyz0123456789"
        encrypted = BytesIO()
        decrypted = BytesIO()
        passphrase.encrypt_io(
            ChunkedReader(plaintext, chunk_size=3),  # ty: ignore[invalid-argument-type]
            encrypted,
            "chunk password",
            armored=armored,
        )
        encrypted.seek(0)
        passphrase.decrypt_io(encrypted, decrypted, "chunk password")
        self.assertEqual(plaintext, decrypted.getvalue())

    def test_roundtrip_io_empty(self):
        encrypted = BytesIO()
        decrypted = BytesIO()
        passphrase.encrypt_io(BytesIO(b""), encrypted, "empty password")
        encrypted.seek(0)
        passphrase.decrypt_io(encrypted, decrypted, "empty password")
        self.assertEqual(b"", decrypted.getvalue())

    def test_roundtrip_io_fail(self):
        with self.assertRaises(TypeError):
            passphrase.encrypt_io("test", BytesIO(), "password")  # ty: ignore[invalid-argument-type]

        with self.assertRaises(TypeError):
            passphrase.encrypt_io(BytesIO(), "test", "password")  # ty: ignore[invalid-argument-type]

        with self.assertRaises(TypeError):
            passphrase.decrypt_io("test", BytesIO(), "password")  # ty: ignore[invalid-argument-type]

        with self.assertRaises(TypeError):
            passphrase.decrypt_io(BytesIO(), "test", "password")  # ty: ignore[invalid-argument-type]

    def test_wrong_passphrase(self):
        encrypted = BytesIO()
        passphrase.encrypt_io(BytesIO(b"secret"), encrypted, "correct password")
        encrypted.seek(0)
        with self.assertRaises(DecryptError) as ctx:
            passphrase.decrypt_io(encrypted, BytesIO(), "wrong password")
        message = str(ctx.exception).lower()
        self.assertNotIn("correct password", message)
        self.assertNotIn("wrong password", message)

    def test_truncated_body_distinct_from_wrong_passphrase(self):
        encrypted = BytesIO()
        passphrase.encrypt_io(BytesIO(b"secret payload data"), encrypted, "password")
        ciphertext = encrypted.getvalue()
        self.assertGreater(len(ciphertext), 8)
        truncated = BytesIO(ciphertext[: len(ciphertext) // 2])

        with self.assertRaises(DecryptError) as wrong_ctx:
            passphrase.decrypt_io(BytesIO(ciphertext), BytesIO(), "not the password")
        with self.assertRaises(DecryptError) as trunc_ctx:
            passphrase.decrypt_io(truncated, BytesIO(), "password")

        self.assertNotEqual(str(wrong_ctx.exception), str(trunc_ctx.exception))

    @unittest.skipUnless(sys.platform.startswith("linux"), "ru_maxrss units are Linux-specific")
    def test_encrypt_io_peak_rss_flat(self):
        # Passphrase encryption pays a large fixed scrypt cost (~hundreds of MiB).
        # Streaming is proven by peak RSS staying flat as plaintext size grows.
        def peak_rss_kb(size: int) -> int:
            code = textwrap.dedent(
                f"""
                import resource
                from pyrage import passphrase

                class ZeroReader:
                    def __init__(self, total, chunk_size=65536):
                        self._remaining = total
                        self._buf = bytes(chunk_size)
                        self._chunk_size = chunk_size

                    def read(self, size=-1):
                        if self._remaining <= 0:
                            return b""
                        if size is None or size < 0:
                            size = self._chunk_size
                        size = min(size, self._chunk_size, self._remaining)
                        self._remaining -= size
                        return self._buf[:size]

                class DiscardWriter:
                    def write(self, data):
                        return len(data)

                    def flush(self):
                        return None

                passphrase.encrypt_io(ZeroReader({size}), DiscardWriter(), "rss password")
                print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
                """
            )
            return int(
                subprocess.check_output([sys.executable, "-c", code], text=True).strip()
            )

        small = peak_rss_kb(8 * 1024 * 1024)
        large = peak_rss_kb(64 * 1024 * 1024)
        # Linux reports ru_maxrss in kilobytes; allow noise but not +56 MiB scaling.
        self.assertLess(
            large - small,
            32 * 1024,
            f"peak RSS scaled with plaintext size: {small} KiB (8 MiB) vs {large} KiB (64 MiB)",
        )

    @unittest.skipUnless(shutil.which("age"), "age CLI not installed")
    def test_stock_age_decrypt(self):
        plaintext = b"interop with stock age"
        password = "age interop password"
        with tempfile.TemporaryDirectory() as tempdir:
            encrypted_path = os.path.join(tempdir, "payload.age")
            decrypted_path = os.path.join(tempdir, "payload.out")
            with open(encrypted_path, "wb") as encrypted:
                passphrase.encrypt_io(BytesIO(plaintext), encrypted, password)

            # age requests the passphrase from a TTY; drive it via a pty.
            import pty

            master, slave = pty.openpty()
            try:
                proc = subprocess.Popen(
                    ["age", "--decrypt", "-o", decrypted_path, encrypted_path],
                    stdin=slave,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                )
                os.close(slave)
                slave = None
                os.write(master, (password + "\n").encode())
                stdout, stderr = proc.communicate(timeout=60)
            finally:
                os.close(master)
                if slave is not None:
                    os.close(slave)

            self.assertEqual(
                proc.returncode,
                0,
                f"age -d failed: stdout={stdout!r} stderr={stderr!r}",
            )
            with open(decrypted_path, "rb") as decrypted:
                self.assertEqual(plaintext, decrypted.read())
