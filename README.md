pyrage
======

[![CI](https://github.com/woodruffw/pyrage/actions/workflows/ci.yml/badge.svg)](https://github.com/woodruffw/pyrage/actions/workflows/ci.yml)

Python bindings for the [Rust implementation of `age`](https://github.com/str4d/rage).

## Index

* [Installation](#installation)
* [Usage](#usage)
* [Development](#development)
* [Licensing](#licensing)

## Installation

You can install `pyrage` with `pip`:

```console
$ python -m pip install pyrage
```

[PEP 561](https://peps.python.org/pep-0561/)-style type stubs are also available:

```console
$ python -m pip install pyrage-stubs
```

See the [development instructions](#development) below for manual installations.

## Usage

### Identity generation (x25519 only)

```python
from pyrage import x25519

ident = x25519.Identity.generate()

# returns the public key
ident.to_public()

# returns the private key
str(ident)
```

### Identity-based encryption and decryption

```python
from pyrage import encrypt, decrypt, ssh, x25519

# load some identities
alice = x25519.Identity.from_str("AGE-SECRET-KEY-...")
bob = ssh.Identity.from_buffer(b"---BEGIN OPENSSH PRIVATE KEY----...")

# load some recipients
carol = x25519.Recipient.from_str("age1z...")
dave = ssh.Recipient.from_str("ssh-ed25519 ...")

# encryption
encrypted = encrypt(b"bob can't be trusted", [carol, dave, alice.to_public()])

# decryption
decrypted = decrypt(encrypted, [alice, bob])
```

### Passphrase encryption and decryption

```python
from pyrage import passphrase

encrypted = passphrase.encrypt(b"something secret", "my extremely secure password")
decrypted = passphrase.decrypt(encrypted, "my extremely secure password")
```

## Development

```console
$ source env/bin/activate
$ make develop
```

## Licensing

`pyrage` is released and distributed under the terms of the [MIT License](./LICENSE).
