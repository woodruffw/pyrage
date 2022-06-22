from typing import Sequence, Union

from . import ssh, x25519

Identity = Union[ssh.Identity, x25519.Identity]
Recipient = Union[ssh.Recipient, x25519.Recipient]

def encrypt(plaintext: bytes, identities: Sequence[Identity]) -> bytes: ...
def decrypt(ciphertext: bytes, recipients: Sequence[Recipient]) -> bytes: ...
