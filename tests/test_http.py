from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from trustverify.authority import Denied, NODES
from trustverify.client import Client, Remote
from trustverify.demo import nodes


def test_three_real_http_processes_binding_and_authority_outage(sandbox):
    authority, _, alice, _ = sandbox
    with nodes(authority) as remotes:
        clients = {node: Client(api, alice, authority.trust) for node, api in remotes.items()}
        for node, client in clients.items():
            assert client.call("access")["service"] == NODES[node]
            assert client.directory(alice.device)["owner"] == "alice"
        envelope = clients["node-a"].envelope("access", {})
        with pytest.raises(Denied, match="binding"):
            remotes["node-b"].request(envelope)
        assert remotes["node-a"].request(envelope)["actor"] == "alice"
        bad = Request(remotes["node-a"].url + "/request", data=b'{"device":"alice-device","device":"operator-device"}',
                      headers={"Content-Type": "application/json"})
        with pytest.raises(HTTPError) as failed:
            urlopen(bad, timeout=5)
        assert failed.value.code == 400
        signed = {node: client.envelope("access", {}) for node, client in clients.items()}
        offline = authority.path.with_suffix(".offline")
        authority.path.rename(offline)
        try:
            for node, api in remotes.items():
                with pytest.raises(Denied) as failed:
                    api.request(signed[node])
                assert failed.value.status == 503
        finally:
            offline.rename(authority.path)


@pytest.mark.parametrize("status,method", [(302, "challenge"), (307, "request")])
def test_client_does_not_follow_mock_service_redirects(status, method):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.path != "/outside":
                self.send_response(status)
                self.send_header("Location", "/outside")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = b'{"nonce":"redirected"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        do_POST = do_GET

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            api = Remote(f"http://127.0.0.1:{server.server_address[1]}", "node-a")
            with pytest.raises(Denied, match="redirect"):
                api.challenge() if method == "challenge" else api.request({})
            assert paths == ["/challenge" if method == "challenge" else "/request"]
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


def test_unauthenticated_flood_is_throttled_without_locking_out_valid_users(sandbox):
    authority, _, alice, _ = sandbox
    junk = {"node": "node-a", "device": "nobody", "version": 1, "nonce": "x",
            "action": "access", "data": {}, "signature": "AA=="}
    with nodes(authority) as remotes:
        statuses = []
        for _ in range(40):
            with pytest.raises(Denied) as failed:
                remotes["node-a"].request(dict(junk))
            statuses.append(failed.value.status)
        assert 429 in statuses
        assert Client(remotes["node-a"], alice, authority.trust).call("access")["actor"] == "alice"
