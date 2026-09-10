from __future__ import annotations

from typing import Optional

class Identity:
    @classmethod
    def from_buffer(cls, buf: bytes, passphrase: Optional[str]) -> Identity:
        ...

class Recipient:
    @classmethod
    def from_str(cls, v: str) -> Recipient:
        ...
