import pytest

from trustverify.authority import Authority
from trustverify.client import Client, Identity, Local


@pytest.fixture
def sandbox(tmp_path):
    admin = Identity.generate("operator-device")
    from trustverify.crypto import public
    authority = Authority.initialize(tmp_path / "authority", tmp_path / "operator", public(admin.key))
    operator = Client(Local(authority), admin, authority.trust)
    alice, bob = Identity.generate("alice-device"), Identity.generate("bob-device")
    for owner, identity in (("alice", alice), ("bob", bob)):
        operator.call("enroll", **identity.enrollment(owner))
        for service in ("frontend", "billing", "secrets"):
            approval = operator.call("approve", owner=owner, service=service)["approval"]
            operator.call("grant", owner=owner, service=service, approval=approval)
    return authority, operator, alice, bob


def client(authority, identity, node="node-a"):
    return Client(Local(authority, node), identity, authority.trust)
