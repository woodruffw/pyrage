from __future__ import annotations
from typing import Sequence, Self, Optional, Protocol


class Callbacks(Protocol):
    def display_message(self, message: str) -> None:
        ...

    def confirm(self, message: str, yes_string: str, no_string: Optional[str]) -> Optional[bool]:
        ...

    def request_public_string(self, description: str) -> Optional[str]:
        ...

    def request_passphrase(self, description: str) -> Optional[str]:
        ...


class Recipient:
    @classmethod
    def from_str(cls, v: str) -> Recipient:
        ...

    def plugin(self) -> str:
        ...


class RecipientPluginV1:
    def __new__(cls, plugin_name: str, recipients: Sequence[Recipient], identities: Sequence[Identity], callbacks: Callbacks) -> Self:
        ...


class Identity:
    @classmethod
    def from_str(cls, v: str) -> Identity:
        ...

    @classmethod
    def default_for_plugin(cls, plugin: str) -> Identity:
        ...

    def plugin(self) -> str:
        ...


class IdentityPluginV1:
    def __new__(cls, plugin_name: str, identities: Sequence[Identity], callbacks: Callbacks) -> Self:
        ...
