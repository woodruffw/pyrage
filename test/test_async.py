import asyncio
import concurrent.futures
import os
import tempfile
import threading
import time
import unittest
from io import BytesIO
from pathlib import Path

from parameterized import parameterized

import pyrage


class TestAsync(unittest.IsolatedAsyncioTestCase):
    @parameterized.expand([(False,), (True,)])
    async def test_roundtrip(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        encrypted = await pyrage.encrypt_async(b"test", [recipient], armored=armored)
        decrypted = await pyrage.decrypt_async(encrypted, [identity])

        self.assertEqual(b"test", decrypted)

    @parameterized.expand([(False,), (True,)])
    async def test_roundtrip_file(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        with tempfile.TemporaryDirectory() as tempdir:
            unencrypted = os.path.join(tempdir, "unencrypted")
            encrypted = os.path.join(tempdir, "encrypted")
            decrypted = os.path.join(tempdir, "decrypted")

            with open(unencrypted, "wb") as file:
                file.write(b"test")

            await pyrage.encrypt_file_async(
                unencrypted, encrypted, [recipient], armored=armored
            )
            await pyrage.decrypt_file_async(encrypted, decrypted, [identity])

            with open(decrypted, "rb") as file:
                self.assertEqual(b"test", file.read())

    async def test_gather(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        plaintexts = [os.urandom(1024) for _ in range(16)]

        encrypted = await asyncio.gather(
            *(pyrage.encrypt_async(p, [recipient]) for p in plaintexts)
        )
        decrypted = await asyncio.gather(
            *(pyrage.decrypt_async(e, [identity]) for e in encrypted)
        )

        self.assertEqual(plaintexts, decrypted)

    async def test_errors_propagate(self):
        with self.assertRaisesRegex(pyrage.EncryptError, "Missing recipients"):
            await pyrage.encrypt_async(b"test", [])

        identity = pyrage.x25519.Identity.generate()
        with self.assertRaises(pyrage.DecryptError):
            await pyrage.decrypt_async(b"not age", [identity])

    async def test_eager_validation(self):
        """
        Bad arguments raise at the call site, not on await, like the sync API.
        """
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        bad = ["not a recipient"]
        with tempfile.TemporaryDirectory() as tempdir:
            path = os.path.join(tempdir, "file")

            calls = [
                lambda: pyrage.encrypt_async(b"test", bad),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.encrypt_async("str", [recipient]),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.decrypt_async(b"test", bad),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.decrypt_async("str", [identity]),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.encrypt_file_async(path, path, bad),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.encrypt_file_async(1, path, [recipient]),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.decrypt_file_async(path, path, bad),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.decrypt_file_async(path, 1, [identity]),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.encrypt_io_async(BytesIO(), BytesIO(), bad),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.encrypt_io_async("str", BytesIO(), [recipient]),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.decrypt_io_async(BytesIO(), BytesIO(), bad),  # ty: ignore[invalid-argument-type]
                lambda: pyrage.decrypt_io_async(BytesIO(), "str", [identity]),  # ty: ignore[invalid-argument-type]
            ]
            for call in calls:
                with self.assertRaises(TypeError):
                    call()

            # Nothing should have been written as a side effect.
            self.assertFalse(os.path.exists(path))

    async def test_type_errors_match_sync(self):
        """
        The eager checks raise exactly what the sync API would: same type,
        message and (on 3.11+) `__notes__`.
        """
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        bad = ["nope"]

        def capture(fn, *args):
            try:
                fn(*args)
            except TypeError as e:
                return type(e), str(e), getattr(e, "__notes__", None)
            self.fail("expected TypeError")

        pairs = [
            (pyrage.encrypt, pyrage.encrypt_async, ("str", [recipient])),
            (pyrage.encrypt, pyrage.encrypt_async, (b"x", bad)),
            (pyrage.decrypt, pyrage.decrypt_async, (1, [identity])),
            (pyrage.decrypt, pyrage.decrypt_async, (b"x", bad)),
            (pyrage.encrypt_file, pyrage.encrypt_file_async, (1, "o", [recipient])),
            (pyrage.encrypt_file, pyrage.encrypt_file_async, ("i", "o", bad)),
            (pyrage.decrypt_file, pyrage.decrypt_file_async, ("i", 1, [identity])),
            (pyrage.encrypt_io, pyrage.encrypt_io_async, ("x", BytesIO(), [recipient])),
            (pyrage.encrypt_io, pyrage.encrypt_io_async, (BytesIO(), BytesIO(), bad)),
            (pyrage.decrypt_io, pyrage.decrypt_io_async, (BytesIO(), "x", [identity])),
        ]
        for sync, async_, args in pairs:
            with self.subTest(fn=async_.__name__, args=args):
                self.assertEqual(capture(sync, *args), capture(async_, *args))

    async def test_arguments_snapshotted(self):
        """
        Mutating a validated list before the worker runs can't sneak a bad
        value past the eager checks.
        """
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        gate = threading.Event()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            # Keep the only worker busy so our call is queued.
            executor.submit(gate.wait)
            recipients: list = [recipient]
            identities: list = [identity]
            encrypted = pyrage.encrypt_async(b"test", recipients, executor=executor)
            recipients.append("not a recipient")
            gate.set()
            encrypted = await encrypted

            gate.clear()
            executor.submit(gate.wait)
            decrypted = pyrage.decrypt_async(encrypted, identities, executor=executor)
            identities.append("not an identity")
            gate.set()

            self.assertEqual(b"test", await decrypted)

    @parameterized.expand([(False,), (True,)])
    async def test_roundtrip_io(self, armored):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()

        encrypted = BytesIO()
        await pyrage.encrypt_io_async(
            BytesIO(b"test"), encrypted, [recipient], armored=armored
        )
        encrypted.seek(0)

        decrypted = BytesIO()
        await pyrage.decrypt_io_async(encrypted, decrypted, [identity])

        self.assertEqual(b"test", decrypted.getvalue())

    async def test_custom_executor(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        submitted = 0

        class Executor(concurrent.futures.ThreadPoolExecutor):
            def submit(self, fn, /, *args, **kwargs):
                nonlocal submitted
                submitted += 1
                return super().submit(fn, *args, **kwargs)

        with Executor(max_workers=1) as executor:
            encrypted = await pyrage.encrypt_async(
                b"test", [recipient], executor=executor
            )
            decrypted = await pyrage.decrypt_async(
                encrypted, [identity], executor=executor
            )

        self.assertEqual(b"test", decrypted)
        self.assertEqual(2, submitted)

    async def test_process_pool_rejected(self):
        recipient = pyrage.x25519.Identity.generate().to_public()
        with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
            with self.assertRaisesRegex(TypeError, "executor must be thread-based"):
                pyrage.encrypt_async(b"test", [recipient], executor=executor)

    async def test_loop_stays_responsive(self):
        identity = pyrage.x25519.Identity.generate()
        recipient = identity.to_public()
        plaintext = b"\x00" * (64 * 1024 * 1024)

        # Track the longest stretch the loop went without running us. Yield
        # with `sleep(0)` rather than a timed sleep, whose resolution is
        # ~15ms on Windows. The clock starts before the call, so a call that
        # blocked the loop (even before returning) would count as one gap.
        start = last = time.monotonic()
        max_gap = 0.0

        async def ticker():
            nonlocal last, max_gap
            while True:
                now = time.monotonic()
                max_gap = max(max_gap, now - last)
                last = now
                await asyncio.sleep(0)

        task = asyncio.create_task(ticker())
        try:
            await pyrage.encrypt_async(plaintext, [recipient])
            # Let the ticker run once more, to record any gap still pending.
            await asyncio.sleep(0)
        finally:
            task.cancel()
        elapsed = time.monotonic() - start

        self.assertLess(max_gap, elapsed / 2)

    async def test_requires_running_loop(self):
        def call():
            return pyrage.encrypt_async(b"test", [])

        # Without a running event loop there's nothing to schedule onto.
        with self.assertRaises(RuntimeError):
            await asyncio.to_thread(call)


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

    def test_passphrase(self):
        encrypted = pyrage.passphrase.encrypt(b"test", "password")
        self.assertReleasesGil(lambda: pyrage.passphrase.encrypt(b"test", "password"))
        self.assertReleasesGil(lambda: pyrage.passphrase.decrypt(encrypted, "password"))

    def test_ssh_encrypted_key(self):
        key = (Path(__file__).parent / "assets" / "ed25519-encrypted").read_bytes()
        self.assertReleasesGil(lambda: pyrage.ssh.Identity.from_buffer(key, "asdfghjkl"))


if __name__ == "__main__":
    unittest.main()
