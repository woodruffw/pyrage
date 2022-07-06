from pathlib import Path

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

assert _ASSETS.is_dir(), "missing test assets directory"


def ssh_keypair(name):
    (pub, priv) = (_ASSETS / f"{name}.pub", _ASSETS / name)
    return (pub.read_text(), priv.read_text())
