"""Track 4 adapter v1 entry point: one JSON request on stdin, one JSON reply on stdout.

Needs only Python 3.12 and pqcrypto==0.4.0. The application logic lives in
trustverify/adapter.py. Diagnostics go to stderr and never include request
values, protected content, keys or the synthetic key material.
"""

import json
import sys

from trustverify.adapter import RequestError, dispatch


def main():
    try:
        request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        response = dispatch(request)
        encoded = json.dumps(response, allow_nan=False, separators=(",", ":"))
    except RequestError as error:
        # RequestError messages are fixed strings that never quote request data.
        print(f"trustverify adapter: {error}", file=sys.stderr)
        sys.stdout.write(json.dumps({"error": str(error)}) + "\n")
        return 1
    except Exception as error:  # noqa: BLE001 - never echo details that could hold secrets
        print(f"trustverify adapter: internal error ({type(error).__name__})", file=sys.stderr)
        sys.stdout.write(json.dumps({"error": "internal error"}) + "\n")
        return 1
    sys.stdout.write(encoded + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
