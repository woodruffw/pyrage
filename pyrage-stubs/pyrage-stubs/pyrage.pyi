from typing import Sequence, Union

from . import x25519

Identity = Union[x25519.Identity]
Recipient = Union[x25519.Recipient]


def encrypt(plaintext: bytes, identities: Sequence[Identity]) -> bytes: ...


def decrypt(ciphertext: bytes, recipients: Sequence[Recipient]) -> bytes: ...
