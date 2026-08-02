from pathlib import Path

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

assert _ASSETS.is_dir(), "missing test assets directory"


def ssh_keypair(name):
    (pub, priv) = (_ASSETS / f"{name}.pub", _ASSETS / name)
    return (pub.read_text(), priv.read_text())


def age_recipient(name):
    # Remove trailing newlines, so that the recipients can be stored as a
    # "normal" text file, with a final newline.
    return (_ASSETS / f"age_{name}_recipient.txt").read_text().removesuffix("\n")
