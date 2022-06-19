pyrage
======

[![CI](https://github.com/woodruffw/pyrage/actions/workflows/ci.yml/badge.svg)](https://github.com/woodruffw/pyrage/actions/workflows/ci.yml)

**Work in progress.**

Python bindings for the [Rust implementation of `age`](https://github.com/str4d/rage).

## Development

```console
$ make develop
$ source env/bin/activate
$ python
```

Then, from within the virtual environment:

```python
>>> import pyrage
>>> pyrage.x25519.Identity.generate()
```
