"""Standard-library helpers shared by the adapter and the full prototype.

Nothing here imports a third-party package, so the grader adapter can use it
in a runtime that only provides Python 3.12 and ``pqcrypto``.
"""

import base64
import json
import os
import tempfile
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    if not isinstance(value, str):
        raise ValueError("expected base64 text")
    decoded = base64.b64decode(value, validate=True)
    if b64(decoded) != value:
        raise ValueError("noncanonical base64 encoding")
    return decoded


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)
