from __future__ import annotations


class Identity:
    @classmethod
    def from_buffer(cls, buf: bytes) -> Identity:
        ...


class Recipient:
    @classmethod
    def from_str(cls, v: str) -> Recipient:
        ...
