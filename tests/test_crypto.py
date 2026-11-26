import base64

import pytest

from trustverify.crypto import new_identity, public, unb64


def test_equivalent_base64_cannot_bypass_key_material_uniqueness():
    encoded = public(new_identity())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert encoded.endswith("=") and not encoded.endswith("==")
    index = alphabet.index(encoded[-2])
    alias = encoded[:-2] + alphabet[index | 1] + "="
    assert base64.b64decode(alias, validate=True) == unb64(encoded)
    with pytest.raises(ValueError, match="noncanonical"):
        unb64(alias)
