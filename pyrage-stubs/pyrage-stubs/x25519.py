from __future__ import annotations


class Identity:
    @classmethod
    def generate(cls) -> Identity: ...

    def to_public(self) -> Recipient: ...


class Recipient:
    @classmethod
    def from_string(cls) -> Recipient: ...
