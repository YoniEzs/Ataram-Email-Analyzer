"""
Tests for attachment analysis heuristics.
"""

from app.services.attachment_analyzer import AttachmentAnalyzerService


def analyze(filename, extension, size=1024, content_type=''):
    return AttachmentAnalyzerService().analyze_single_attachment({
        'filename': filename,
        'extension': extension,
        'content_type': content_type,
        'size': size,
    })


def test_flags_executable_attachment():
    result = analyze('setup.exe', 'exe')
    assert 'executable_file' in result['issues']
    assert result['severity'] == 'critical'


def test_whitespace_padded_extension_still_flagged_as_executable():
    # "invoice.exe " used to slip past every extension check because the
    # extracted extension kept its trailing spaces.
    result = analyze('invoice.exe ', 'exe ')
    assert 'executable_file' in result['issues']
    assert 'hidden_extension' in result['issues']
    assert result['severity'] == 'critical'


def test_hidden_extension_does_not_downgrade_severity():
    result = analyze('payload.exe   ', 'exe   ', size=2048)
    assert result['severity'] == 'critical'


def test_double_extension_with_padding_detected():
    result = analyze('report.pdf    .exe', 'exe')
    assert 'double_extension' in result['issues']
    assert result['severity'] == 'critical'


def test_benign_document_not_flagged():
    result = analyze('quarterly-report.pdf', 'pdf')
    assert result['issues'] == []
    assert result['is_suspicious'] is False


def test_uppercase_extension_not_marked_hidden():
    result = analyze('TOOL.EXE', 'EXE')
    assert 'executable_file' in result['issues']
    assert 'hidden_extension' not in result['issues']
