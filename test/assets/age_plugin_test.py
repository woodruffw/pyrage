#!/usr/bin/env python3
"""
A minimal age plugin used by the test suite, implementing just enough of the
recipient-v1 and identity-v1 state machines for a round trip.

It "wraps" file keys by storing them verbatim in the stanza body, so it offers
no security whatsoever. Both phases emit a `msg` command first, which lets the
tests check that callbacks are invoked.
"""

import base64
import sys


def read_stanza(inp):
    line = inp.readline()
    if not line:
        return None
    arrow, tag, *args = line.rstrip("\n").split(" ")
    assert arrow == "->", line

    lines = []
    while True:
        body_line = inp.readline().rstrip("\n")
        lines.append(body_line)
        if len(body_line) < 64:
            break
    b64 = "".join(lines)
    body = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    return tag, args, body


def write_stanza(out, tag, args=(), body=b""):
    b64 = base64.b64encode(body).decode().rstrip("=")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    if not lines or len(lines[-1]) == 64:
        lines.append("")
    out.write(" ".join(["->", tag, *args]) + "\n" + "\n".join(lines) + "\n")
    out.flush()


def expect_ok(inp):
    stanza = read_stanza(inp)
    assert stanza is not None and stanza[0] == "ok", stanza


def main():
    mode = sys.argv[1].removeprefix("--age-plugin=")
    inp, out = sys.stdin, sys.stdout

    # Phase 1: collect everything the client sends until `done`.
    received = []
    while (stanza := read_stanza(inp)) is not None and stanza[0] != "done":
        received.append(stanza)

    # Phase 2: respond.
    write_stanza(out, "msg", body=f"hello from {mode}".encode())
    expect_ok(inp)

    for tag, args, body in received:
        if mode == "recipient-v1" and tag == "wrap-file-key":
            write_stanza(out, "recipient-stanza", ["0", "test"], body)
            expect_ok(inp)
        elif mode == "identity-v1" and tag == "recipient-stanza" and args[1] == "test":
            write_stanza(out, "file-key", [args[0]], body)
            expect_ok(inp)

    write_stanza(out, "done")


if __name__ == "__main__":
    main()
