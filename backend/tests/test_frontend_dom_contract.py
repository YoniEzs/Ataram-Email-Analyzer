"""
Contract tests to keep frontend HTML and JS ID expectations aligned.
"""

import re
from pathlib import Path


INDEX_HTML_PATH = Path(__file__).resolve().parents[2] / "frontend" / "src" / "index.html"

REQUIRED_IDS = {
    "dropZone",
    "fileInput",
    "apiKeyInput",
    "apiDestination",
    "progressBar",
    "progressStep",
    "resultsSection",
    "errorSection",
    "errorMessage",
    "retryButton",
    "exportBar",
    "copyArtifactsBtn",
    "downloadReportBtn",
    "printReportBtn",
    "historySection",
    "historyList",
    "historyDisclosure",
    "clearHistoryBtn",
    "langToggle",
}

EXPECTED_SCRIPT_ORDER = [
    "js/theme-init.js",
    "runtime-config.js",
    "js/i18n.js",
    "js/config.js",
    "js/api.js",
    "js/ui.js",
    "js/results.js",
    "js/app.js",
]


def test_index_html_contains_required_ids_for_ui_controller():
    html = INDEX_HTML_PATH.read_text(encoding="utf-8")
    present_ids = set(re.findall(r'\bid="([^"]+)"', html))
    missing_ids = REQUIRED_IDS - present_ids

    assert not missing_ids, f"Missing required DOM ids: {sorted(missing_ids)}"


def test_index_html_preserves_required_script_load_order():
    html = INDEX_HTML_PATH.read_text(encoding="utf-8")
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', html)

    assert scripts == EXPECTED_SCRIPT_ORDER


RESULTS_JS_PATH = Path(__file__).resolve().parents[2] / "frontend" / "src" / "js" / "results.js"


def test_attachment_and_url_cards_offer_no_third_party_lookup():
    """Files and URLs are checked with open-source tooling only.

    The analyzer never fetches a URL and never executes or extracts an
    attachment, so nothing about the payload leaves the machine. Rendering a
    "look this hash/domain up on VirusTotal" button would undo that by handing
    the payload to a third party on the analyst's behalf. Reputation links for
    the sending IP and sender domain are a separate matter and stay: they
    describe infrastructure, not the message contents.
    """
    source = RESULTS_JS_PATH.read_text(encoding="utf-8")

    assert "virustotal.com/gui/file" not in source, (
        "attachment hashes must not be pivoted to a third-party service"
    )

    # The domain pivot is allowed exactly once, in the shared value renderer
    # used for sender-domain artifacts -- never in the URL card.
    assert source.count("virustotal.com/gui/domain") <= 1, (
        "the URLs card must not pivot extracted domains to a third party"
    )

    renderers = source.split("renderAttachments")
    assert len(renderers) > 1, "renderAttachments not found - test out of date"
    assert "virustotal" not in renderers[1].split("renderValue")[0].lower(), (
        "no third-party lookup may be rendered inside the attachments card"
    )
