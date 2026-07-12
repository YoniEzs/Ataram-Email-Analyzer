"""
Contract tests for direct domain and IP lookup API endpoints.
"""


def test_check_domain_api_returns_dns_and_whois_data(client, monkeypatch):
    from app.services import dns_checker as dns_checker_module
    from app.services import whois_service as whois_service_module

    calls = {"dns_timeout": None, "whois_timeout": None}

    class DummyDNSCheckerService:
        def __init__(self, timeout=5):
            calls["dns_timeout"] = timeout

        def check_spf(self, domain):
            assert domain == "example.com"
            return "v=spf1 include:_spf.example.com -all"

        def check_dmarc(self, domain):
            assert domain == "example.com"
            return "v=DMARC1; p=reject"

    class DummyWhoisService:
        def __init__(self, timeout=10):
            calls["whois_timeout"] = timeout

        def lookup(self, domain):
            assert domain == "example.com"
            return {"domain": domain, "registrar": "Example Registrar"}

    monkeypatch.setattr(dns_checker_module, "DNSCheckerService", DummyDNSCheckerService)
    monkeypatch.setattr(whois_service_module, "WhoisService", DummyWhoisService)
    client.application.config["ENABLE_WHOIS"] = True
    client.application.config["DNS_TIMEOUT"] = 3
    client.application.config["WHOIS_TIMEOUT"] = 7

    response = client.post("/api/check/domain", json={"domain": " Example.COM "})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload == {
        "domain": "example.com",
        "spf": "v=spf1 include:_spf.example.com -all",
        "dmarc": "v=DMARC1; p=reject",
        "whois": {"domain": "example.com", "registrar": "Example Registrar"},
    }
    assert calls == {"dns_timeout": 3, "whois_timeout": 7}


def test_check_domain_api_skips_whois_when_disabled(client, monkeypatch):
    from app.services import dns_checker as dns_checker_module

    class DummyDNSCheckerService:
        def __init__(self, timeout=5):
            pass

        def check_spf(self, domain):
            return None

        def check_dmarc(self, domain):
            return None

    monkeypatch.setattr(dns_checker_module, "DNSCheckerService", DummyDNSCheckerService)
    client.application.config["ENABLE_WHOIS"] = False

    response = client.post("/api/check/domain", json={"domain": "example.com"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["whois"] is None


def test_check_ip_api_returns_reputation_data(client, monkeypatch):
    from app.services import ip_reputation as ip_reputation_module

    calls = {"api_key": None, "timeout": None, "ip": None}

    class DummyIPReputationService:
        def __init__(self, api_key=None, timeout=10):
            calls["api_key"] = api_key
            calls["timeout"] = timeout

        def check_ip(self, ip):
            calls["ip"] = ip
            return {
                "ipAddress": ip,
                "abuseConfidenceScore": 12,
                "totalReports": 2,
            }

    monkeypatch.setattr(
        ip_reputation_module,
        "IPReputationService",
        DummyIPReputationService,
    )
    client.application.config["ENABLE_ABUSEIPDB"] = True
    client.application.config["HTTP_TIMEOUT"] = 4

    response = client.post(
        "/api/check/ip",
        json={"ip": "8.8.8.8", "abuseipdb_key": "request-key"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 12,
        "totalReports": 2,
    }
    assert calls == {"api_key": "request-key", "timeout": 4, "ip": "8.8.8.8"}


def test_check_ip_api_can_use_configured_api_key(client, monkeypatch):
    from app.services import ip_reputation as ip_reputation_module

    class DummyIPReputationService:
        def __init__(self, api_key=None, timeout=10):
            self.api_key = api_key

        def check_ip(self, ip):
            return {"ipAddress": ip, "apiKeyUsed": self.api_key}

    monkeypatch.setattr(
        ip_reputation_module,
        "IPReputationService",
        DummyIPReputationService,
    )
    client.application.config["ENABLE_ABUSEIPDB"] = True
    client.application.config["ABUSEIPDB_KEY"] = "configured-key"

    response = client.post("/api/check/ip", json={"ip": "8.8.4.4"})

    assert response.status_code == 200
    assert response.get_json() == {"ipAddress": "8.8.4.4", "apiKeyUsed": "configured-key"}
