import pytest


@pytest.fixture
def sandbox(tmp_path):
    # Imported lazily so the adapter tests run with only pqcrypto installed.
    from trustverify.authority import Authority
    from trustverify.client import Client, Identity, Local
    from trustverify.crypto import public
    admin, second = Identity.generate("operator-device"), Identity.generate("officer-device")
    authority = Authority.initialize(tmp_path / "authority", tmp_path / "operator", public(admin.key),
                                     [("security-officer", second.device, public(second.key))])
    operator = Client(Local(authority), admin, authority.trust)
    # Second administrator: approvals must come from someone other than the granting admin.
    operator.officer = Client(Local(authority), second, authority.trust)
    alice, bob = Identity.generate("alice-device"), Identity.generate("bob-device")
    for owner, identity in (("alice", alice), ("bob", bob)):
        operator.call("enroll", **identity.enrollment(owner))
        for service in ("frontend", "billing", "secrets"):
            approval = operator.officer.call("approve", owner=owner, service=service)["approval"]
            operator.call("grant", owner=owner, service=service, approval=approval)
    return authority, operator, alice, bob


def client(authority, identity, node="node-a"):
    from trustverify.client import Client, Local
    return Client(Local(authority, node), identity, authority.trust)
