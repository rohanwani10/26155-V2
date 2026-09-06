from app.vendors import VendorProfile, detect_vendor, register_vendor, registered_vendor_names


def test_cisco_ios_is_registered_by_default():
    assert "cisco_ios" in registered_vendor_names()


def test_cisco_ios_detected_from_version_dump():
    profile = detect_vendor("hostname x\n", "Cisco IOS Software, Version 15.0\n")
    assert profile is not None
    assert profile.name == "cisco_ios"


def test_unrecognized_vendor_returns_none():
    profile = detect_vendor("some config\n", "some unrelated version dump\n")
    assert profile is None


def test_first_matching_registered_profile_wins():
    register_vendor(
        VendorProfile(
            name="_test_vendor",
            detect=lambda _config, version: "TESTMARKER" in version,
            parse_facts=lambda _redacted: None,
            parse_identity=lambda _version: None,
        )
    )
    profile = detect_vendor("irrelevant", "TESTMARKER present")
    assert profile is not None
    assert profile.name == "_test_vendor"
