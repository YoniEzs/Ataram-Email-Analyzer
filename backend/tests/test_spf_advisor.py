"""Tests for advisory SPF re-evaluation.

The single most important property here is negative: an advisory result must
never reach the authentication block and must never move the risk score. Both
of its inputs come from headers an attacker controls.
"""

import pytest

from app.services import spf_advisor
from app.services.spf_advisor import SPFAdvisorService

PUBLIC_IP = '93.184.216.34'


class _FakeSpf:
    def __init__(self, result='pass', explanation='ok', raises=None):
        self.result = result
        self.explanation = explanation
        self.raises = raises
        self.calls = []

    def check2(self, **kwargs):
        self.calls.append(kwargs)
        if self.raises:
            raise self.raises
        return self.result, self.explanation


@pytest.fixture
def fake_spf(monkeypatch):
    fake = _FakeSpf()
    monkeypatch.setattr(spf_advisor, '_spf', fake)
    monkeypatch.setattr(spf_advisor, 'SPF_AVAILABLE', True)
    return fake


@pytest.mark.parametrize('result', [
    'pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror',
])
def test_every_spf_result_is_returned_verbatim(fake_spf, result):
    fake_spf.result = result
    out = SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    )
    assert out['result'] == result


def test_result_is_always_marked_untrusted_and_unscored(fake_spf):
    out = SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    )
    assert out['trusted'] is False
    assert out['advisory'] is True
    assert out['affects_risk_score'] is False
    assert out['disclaimer']
    assert 'can be forged' in out['disclaimer']


def test_inputs_and_their_provenance_are_recorded(fake_spf):
    out = SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    )
    assert out['evaluated_ip'] == PUBLIC_IP
    assert out['evaluated_mail_from'] == 'bounce@sender.com'
    assert out['evaluated_helo'] == 'mail.sender.com'
    assert out['ip_source'] == 'received_header_chain'
    assert out['mail_from_source'] == 'return_path_header'


def test_query_time_is_bounded(fake_spf):
    """pyspf defaults to 20s with TCP fallback, which would blow the deadline."""
    SPFAdvisorService(timeout=6).evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    )
    assert fake_spf.calls[0]['querytime'] == 6
    assert fake_spf.calls[0]['timeout'] == 6


def test_missing_helo_falls_back_to_the_sender_domain(fake_spf):
    out = SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo=None
    )
    assert out['evaluated_helo'] == 'sender.com'


def test_unknown_result_is_normalised_to_permerror(fake_spf):
    fake_spf.result = 'something-unexpected'
    out = SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    )
    assert out['result'] == 'permerror'


def test_library_exception_yields_none(monkeypatch):
    monkeypatch.setattr(spf_advisor, '_spf', _FakeSpf(raises=RuntimeError('boom')))
    monkeypatch.setattr(spf_advisor, 'SPF_AVAILABLE', True)
    assert SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    ) is None


@pytest.mark.parametrize('ip', ['192.168.1.1', '127.0.0.1', None, '', 'garbage'])
def test_non_public_ips_are_never_evaluated(fake_spf, ip):
    assert SPFAdvisorService().evaluate(
        ip=ip, mail_from='bounce@sender.com', helo='mail.sender.com'
    ) is None
    assert fake_spf.calls == []


def test_unusable_domains_are_never_evaluated(fake_spf):
    assert SPFAdvisorService().evaluate(
        ip=PUBLIC_IP, mail_from='bounce@localhost', helo='localhost'
    ) is None
    assert fake_spf.calls == []


def test_missing_library_degrades_to_none(monkeypatch):
    monkeypatch.setattr(spf_advisor, 'SPF_AVAILABLE', False)
    service = SPFAdvisorService()
    assert service.available is False
    assert service.evaluate(
        ip=PUBLIC_IP, mail_from='bounce@sender.com', helo='mail.sender.com'
    ) is None
