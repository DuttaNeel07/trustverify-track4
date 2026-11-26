"""Endpoint signing credentials and the local HTTP client."""

import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .authority import Denied, NODES
from .crypto import atomic_write, canonical, load_private, new_identity, private_bytes, public, sign, verify


class Identity:
    def __init__(self, device, key, version=1):
        self.device, self.key, self.version = device, key, version

    @classmethod
    def generate(cls, device):
        from .authority import identifier
        return cls(identifier(device), new_identity())

    def enrollment(self, owner):
        value = {"device": self.device, "owner": owner, "public": public(self.key)}
        return {**value, "proof": sign(self.key, "enroll", value)}

    def rotation(self, new_key):
        value = {"device": self.device, "version": self.version + 1, "public": public(new_key)}
        return {"public": value["public"], "proof": sign(new_key, "rotation", value)}

    def save(self, directory):
        directory = Path(directory)
        atomic_write(directory / f"v{self.version}.pem", private_bytes(self.key))
        atomic_write(directory / "identity.json", canonical({"device": self.device, "version": self.version}))

    @classmethod
    def load(cls, directory, version=None):
        directory = Path(directory)
        value = json.loads((directory / "identity.json").read_bytes())
        version = version or value["version"]
        return cls(value["device"], load_private((directory / f"v{version}.pem").read_bytes()), version)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Remote:
    def __init__(self, url, node):
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("mock clients support only http://127.0.0.1:PORT")
        if node not in NODES:
            raise ValueError("unknown node")
        self.url, self.node = url, node
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, path, value=None):
        request = Request(self.url + path, data=canonical(value) if value is not None else None,
                          headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                return json.load(response)
        except HTTPError as exc:
            with exc:
                if 300 <= exc.code < 400:
                    raise Denied("mock service redirect refused", exc.code) from exc
                raise Denied(json.load(exc).get("error", "request failed"), exc.code) from exc

    def challenge(self, device=None):
        return self._request("/challenge" + ("?device=" + quote(device, safe="") if device else ""))["nonce"]

    def request(self, value):
        return self._request("/request", value)



class Local:
    """Same signed envelope, without HTTP, for focused transaction tests."""

    def __init__(self, authority, node="node-a"):
        self.authority, self.node = authority, node

    def challenge(self, device=None):
        return self.authority.challenge(self.node, device)

    def request(self, value):
        return self.authority.execute(self.node, value)



class Client:
    def __init__(self, api, identity, trust):
        self.api, self.identity, self.trust = api, identity, trust

    def envelope(self, action, data):
        value = {"node": self.api.node, "device": self.identity.device,
                 "version": self.identity.version, "nonce": self.api.challenge(self.identity.device),
                 "action": action, "data": data}
        return {**value, "signature": sign(self.identity.key, "request", value)}

    def call(self, action, **data):
        return self.api.request(self.envelope(action, data))

    def directory(self, device):
        # Directory lookups are an authenticated action, so device IDs and owners can't be enumerated.
        response = self.call("directory", device=device)
        verify(self.trust["audit_public"], "directory", response["entry"], response["signature"])
        entry = response["entry"]
        if entry["id"] != device or entry["revoked"] or entry["state"] != "active":
            raise Denied("directory credential unavailable")
        return entry
