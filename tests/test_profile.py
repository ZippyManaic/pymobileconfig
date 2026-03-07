import plistlib

import pytest

from pymobileconfig import Profile
from pymobileconfig.payloads import ManagedAppConfig, SCEP, TrustedCertificate


DUMMY_DER = b"\x30\x82\x01\x00"  # not a real cert — just DER-like bytes for structure tests


class TestProfile:
    def test_to_dict_structure(self):
        profile = Profile(display_name="Test Profile", organisation="Acme")
        d = profile.to_dict()

        assert d["PayloadDisplayName"] == "Test Profile"
        assert d["PayloadOrganization"] == "Acme"
        assert d["PayloadType"] == "Configuration"
        assert d["PayloadVersion"] == 1
        assert d["PayloadRemovalDisallowed"] is False
        assert isinstance(d["PayloadUUID"], str)
        assert len(d["PayloadUUID"]) == 36
        assert d["PayloadContent"] == []

    def test_identifier_defaults_from_organisation(self):
        profile = Profile(display_name="X", organisation="My Corp")
        assert profile.identifier.startswith("com.mycorp.profile.")

    def test_custom_identifier(self):
        profile = Profile(
            display_name="X",
            organisation="Acme",
            identifier="com.example.custom",
        )
        assert profile.identifier == "com.example.custom"

    def test_add_returns_self_for_chaining(self):
        profile = Profile(display_name="X", organisation="Acme")
        result = profile.add(ManagedAppConfig(display_name="Y", config={}))
        assert result is profile

    def test_payloads_appear_in_content(self):
        profile = Profile(display_name="X", organisation="Acme")
        profile.add(ManagedAppConfig(display_name="App Config", config={"key": "value"}))
        d = profile.to_dict()
        assert len(d["PayloadContent"]) == 1
        assert d["PayloadContent"][0]["PayloadDisplayName"] == "App Config"

    def test_dumps_returns_valid_plist(self):
        profile = Profile(display_name="X", organisation="Acme")
        data = profile.dumps()
        parsed = plistlib.loads(data)
        assert parsed["PayloadDisplayName"] == "X"

    def test_write_creates_file(self, tmp_path):
        profile = Profile(display_name="X", organisation="Acme")
        out = tmp_path / "test.mobileconfig"
        profile.write(out)
        assert out.exists()
        parsed = plistlib.loads(out.read_bytes())
        assert parsed["PayloadDisplayName"] == "X"

    def test_removal_disallowed(self):
        profile = Profile(
            display_name="X", organisation="Acme", removal_disallowed=True
        )
        assert profile.to_dict()["PayloadRemovalDisallowed"] is True

    def test_description(self):
        profile = Profile(
            display_name="X", organisation="Acme", description="A test profile"
        )
        assert profile.to_dict()["PayloadDescription"] == "A test profile"

    def test_multiple_payloads(self):
        profile = (
            Profile(display_name="X", organisation="Acme")
            .add(ManagedAppConfig(display_name="Config", config={}))
            .add(ManagedAppConfig(display_name="Config 2", config={}))
        )
        assert len(profile.to_dict()["PayloadContent"]) == 2


class TestBasePayloadFields:
    def test_payload_uuid_is_unique(self):
        p1 = ManagedAppConfig(display_name="A", config={})
        p2 = ManagedAppConfig(display_name="B", config={})
        assert p1._uuid != p2._uuid

    def test_payload_identifier_includes_profile_identifier(self):
        p = ManagedAppConfig(display_name="A", config={})
        d = p.to_dict("com.example.profile")
        assert d["PayloadIdentifier"].startswith("com.example.profile.")

    def test_payload_version_is_1(self):
        p = ManagedAppConfig(display_name="A", config={})
        assert p.to_dict("com.example")["PayloadVersion"] == 1
