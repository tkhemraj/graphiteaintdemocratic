from graphiteaintdemocratic.iocs import (
    load_domains,
    load_ips,
    load_log_strings,
    load_processes,
    load_file_artifacts,
    load_all_known_ips,
)


def test_domains_load():
    domains = load_domains()
    assert len(domains) > 0
    for d in domains:
        assert "domain" in d
        assert d["domain"]


def test_ips_load():
    ips = load_ips()
    assert len(ips) > 0
    for entry in ips:
        assert "ip" in entry
        # basic sanity: looks like an IP
        assert entry["ip"].count(".") == 3


def test_log_strings_contain_key_indicators():
    strings = load_log_strings()
    names = [s["string"] for s in strings]
    assert "BIGPRETZEL" in names
    assert "SMALLPRETZEL" in names
    assert "ATTACKER1" in names


def test_log_strings_have_metadata():
    strings = load_log_strings()
    bigpretzel = next(s for s in strings if s["string"] == "BIGPRETZEL")
    assert bigpretzel["platform"] == "android"
    assert bigpretzel["confidence"] == "HIGH"


def test_log_strings_platform_filter():
    android = load_log_strings(platform="android")
    ios = load_log_strings(platform="ios")
    assert all("android" in s["platform"] for s in android)
    assert all("ios" in s["platform"] for s in ios)
    android_names = [s["string"] for s in android]
    ios_names = [s["string"] for s in ios]
    assert "BIGPRETZEL" in android_names
    assert "SMALLPRETZEL" in ios_names
    assert "ATTACKER1" in ios_names


def test_known_ips_set():
    ip_set = load_all_known_ips()
    assert isinstance(ip_set, set)
    assert "46.183.184.91" in ip_set
    assert "84.110.122.27" in ip_set
