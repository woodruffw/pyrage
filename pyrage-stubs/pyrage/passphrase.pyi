def encrypt(plaintext: bytes, passphrase: str, armored: bool = False) -> bytes: ...
def decrypt(ciphertext: bytes, passphrase: str, armored: bool = False) -> bytes: ...
