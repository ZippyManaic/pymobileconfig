import base64
import plistlib
from pathlib import Path

import pytest

from pymobileconfig.payloads import ManagedAppConfig, PKCS12, SCEP, TrustedCertificate
from pymobileconfig.payloads.scep import _normalise_subject
from pymobileconfig.payloads.trusted_cert import _pem_to_der


# Minimal PEM-wrapped bytes for testing (content is arbitrary — not a real cert)
_RAW_BYTES = b"\x30\x82\x00\x01\x02\x03"
_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    + base64.encodebytes(_RAW_BYTES)
    + b"-----END CERTIFICATE-----\n"
)


class TestTrustedCertificate:
    def test_der_bytes_passed_through(self):
        p = TrustedCertificate(display_name="Root CA", certificate=_RAW_BYTES)
        d = p.to_dict("com.example")
        assert d["PayloadCertificateData"] == _RAW_BYTES

    def test_pem_bytes_converted_to_der(self):
        p = TrustedCertificate(display_name="Root CA", certificate=_PEM)
        d = p.to_dict("com.example")
        assert d["PayloadCertificateData"] == _RAW_BYTES

    def test_pem_path_loaded_and_converted(self, tmp_path):
        pem_file = tmp_path / "ca.crt"
        pem_file.write_bytes(_PEM)
        p = TrustedCertificate(display_name="Root CA", certificate=pem_file)
        d = p.to_dict("com.example")
        assert d["PayloadCertificateData"] == _RAW_BYTES

    def test_payload_type(self):
        p = TrustedCertificate(display_name="Root CA", certificate=_RAW_BYTES)
        assert p.to_dict("com.example")["PayloadType"] == "com.apple.security.root"

    def test_custom_payload_type(self):
        p = TrustedCertificate(
            display_name="Inter CA",
            certificate=_RAW_BYTES,
            payload_type="com.apple.security.pkcs1",
        )
        assert p.to_dict("com.example")["PayloadType"] == "com.apple.security.pkcs1"

    def test_pem_to_der_utility(self):
        assert _pem_to_der(_PEM) == _RAW_BYTES


class TestSCEP:
    def _make(self, **kwargs):
        defaults = dict(
            display_name="Device Cert",
            url="https://ca.example.com:9000/scep/scep",
            challenge="secret",
            subject=[("CN", "device-001"), ("OU", "backend"), ("O", "Acme")],
        )
        defaults.update(kwargs)
        return SCEP(**defaults)

    def test_payload_type(self):
        p = self._make()
        assert p.to_dict("com.example")["PayloadType"] == "com.apple.security.scep"

    def test_url_in_content(self):
        p = self._make(url="https://ca.example.com:9000/scep/scep")
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["URL"] == "https://ca.example.com:9000/scep/scep"

    def test_challenge_in_content(self):
        p = self._make(challenge="mysecret")
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["Challenge"] == "mysecret"

    def test_subject_normalised_from_pairs(self):
        p = self._make(subject=[("CN", "dev"), ("OU", "backend")])
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["Subject"] == [[["CN", "dev"]], [["OU", "backend"]]]

    def test_subject_normalised_from_flat_list_of_lists(self):
        # Test the branch handling [["CN", "dev"], ["OU", "backend"]]
        p = self._make(subject=[["CN", "dev"], ["OU", "backend"]])
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["Subject"] == [[["CN", "dev"]], [["OU", "backend"]]]

    def test_subject_nested_format_passed_through(self):
        nested = [[["CN", "dev"]], [["OU", "backend"]]]
        p = self._make(subject=nested)
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["Subject"] == nested

    def test_defaults(self):
        p = self._make()
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["KeyType"] == "RSA"
        assert content["KeySize"] == 2048
        assert content["KeyUsage"] == 5
        assert content["Retries"] == 3
        assert content["RetryDelay"] == 10
        assert content["Name"] == "scep"
        assert content["KeyIsExtractable"] is False

    def test_key_is_extractable(self):
        p = self._make(key_is_extractable=True)
        assert p.to_dict("com.example")["PayloadContent"]["KeyIsExtractable"] is True

    def test_subject_alt_name(self):
        san = {"dnsName": "example.com"}
        p = self._make(subject_alt_name=san)
        assert p.to_dict("com.example")["PayloadContent"]["SubjectAltName"] == san

    def test_ca_fingerprint(self):
        p = self._make(ca_fingerprint=b"FINGERPRINT")
        assert (
            p.to_dict("com.example")["PayloadContent"]["CAFingerprint"] == b"FINGERPRINT"
        )

    def test_keychain_access_groups_included_when_set(self):
        p = self._make(
            keychain_access_groups=["$(AppIdentifierPrefix)com.example.app"]
        )
        content = p.to_dict("com.example")["PayloadContent"]
        assert content["KeychainAccessGroups"] == [
            "$(AppIdentifierPrefix)com.example.app"
        ]

    def test_keychain_access_groups_absent_when_empty(self):
        p = self._make()
        content = p.to_dict("com.example")["PayloadContent"]
        assert "KeychainAccessGroups" not in content


class TestPKCS12:
    _P12_BYTES = b"\x30\x82\x00\x01\x02\x03\x04\x05"  # fake .p12 bytes

    def test_payload_type(self):
        p = PKCS12(display_name="DeviceServer Cert", pkcs12=self._P12_BYTES)
        assert p.to_dict("com.example")["PayloadType"] == "com.apple.security.pkcs12"

    def test_bytes_embedded_as_payload_content(self):
        p = PKCS12(display_name="Server Cert", pkcs12=self._P12_BYTES)
        d = p.to_dict("com.example")
        assert d["PayloadContent"] == self._P12_BYTES

    def test_path_loaded(self, tmp_path):
        p12_file = tmp_path / "server.p12"
        p12_file.write_bytes(self._P12_BYTES)
        p = PKCS12(display_name="Server Cert", pkcs12=p12_file)
        assert p.to_dict("com.example")["PayloadContent"] == self._P12_BYTES

    def test_password_included_when_set(self):
        p = PKCS12(
            display_name="Server Cert",
            pkcs12=self._P12_BYTES,
            password="secret",
        )
        d = p.to_dict("com.example")
        assert d["Password"] == "secret"

    def test_password_absent_when_empty(self):
        p = PKCS12(display_name="Server Cert", pkcs12=self._P12_BYTES)
        assert "Password" not in p.to_dict("com.example")

    def test_survives_plist_round_trip(self):
        from pymobileconfig import Profile

        profile = Profile(display_name="X", organisation="Acme")
        profile.add(PKCS12(
            display_name="Server Cert",
            pkcs12=self._P12_BYTES,
            password="secret",
        ))
        parsed = plistlib.loads(profile.dumps())
        payload = parsed["PayloadContent"][0]
        assert payload["PayloadType"] == "com.apple.security.pkcs12"
        assert payload["PayloadContent"] == self._P12_BYTES
        assert payload["Password"] == "secret"


class TestManagedAppConfig:
    def test_payload_type(self):
        p = ManagedAppConfig(display_name="App Config", config={})
        assert (
            p.to_dict("com.example")["PayloadType"]
            == "com.apple.configuration.managed"
        )

    def test_config_keys_merged_into_dict(self):
        p = ManagedAppConfig(
            display_name="App Config",
            config={"api_base_url": "https://api.example.com", "timeout": 30},
        )
        d = p.to_dict("com.example")
        assert d["api_base_url"] == "https://api.example.com"
        assert d["timeout"] == 30

    def test_empty_config(self):
        p = ManagedAppConfig(display_name="App Config", config={})
        d = p.to_dict("com.example")
        assert d["PayloadType"] == "com.apple.configuration.managed"

    def test_nested_config(self):
        p = ManagedAppConfig(
            display_name="App Config",
            config={"servers": ["a.example.com", "b.example.com"]},
        )
        d = p.to_dict("com.example")
        assert d["servers"] == ["a.example.com", "b.example.com"]

    def test_config_survives_plist_round_trip(self):
        import plistlib
        from pymobileconfig import Profile

        profile = Profile(display_name="X", organisation="Acme")
        profile.add(
            ManagedAppConfig(
                display_name="Config",
                config={"api_base_url": "https://api.example.com"},
            )
        )
        parsed = plistlib.loads(profile.dumps())
        payload = parsed["PayloadContent"][0]
        assert payload["api_base_url"] == "https://api.example.com"


def test_normalise_subject_utility():
    # Branch 1: Empty
    assert _normalise_subject([]) == []

    # Branch 2: List of tuples
    pairs = [("CN", "dev"), ("OU", "backend")]
    expected = [[["CN", "dev"]], [["OU", "backend"]]]
    assert _normalise_subject(pairs) == expected

    # Branch 3: Flat list of lists
    flat_lists = [["CN", "dev"], ["OU", "backend"]]
    assert _normalise_subject(flat_lists) == expected

    # Branch 4: Already nested (pass-through)
    assert _normalise_subject(expected) == expected
