from io import BufferedIOBase
from typing import Sequence, Union

from pyrage import passphrase, plugin, ssh, x25519
from pyrage.plugin import IdentityPluginV1, RecipientPluginV1
from pyrage.ssh import Identity as SSHIdentity
from pyrage.ssh import Recipient as SSHRecipient
from pyrage.x25519 import Identity as X25519Identity
from pyrage.x25519 import Recipient as X25519Recipient

_Identity = Union[SSHIdentity, X25519Identity, IdentityPluginV1]
_Recipient = Union[SSHRecipient, X25519Recipient, RecipientPluginV1]

__all__ = (
    "ssh",
    "x25519",
    "passphrase",
    "plugin",
    "encrypt",
    "encrypt_file",
    "encrypt_io",
    "decrypt",
    "decrypt_file",
    "decrypt_io",
    "RecipientError",
    "IdentityError",
)


class RecipientError(Exception):
    ...

class IdentityError(Exception):
    ...


def encrypt(plaintext: bytes, recipients: Sequence[_Recipient]) -> bytes: ...
def encrypt_file(infile: str, outfile: str, recipients: Sequence[_Recipient]) -> None: ...
def encrypt_io(in_io: BufferedIOBase, out_io: BufferedIOBase, recipients: Sequence[_Recipient]) -> bytes: ...

def decrypt(ciphertext: bytes, identities: Sequence[_Identity]) -> bytes: ...
def decrypt_file(infile: str, outfile: str, identities: Sequence[_Identity]) -> None: ...
def decrypt_io(in_io: BufferedIOBase, out_io: BufferedIOBase, identities: Sequence[_Identity]) -> None: ...
