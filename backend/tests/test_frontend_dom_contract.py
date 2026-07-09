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
    "progressBar",
    "progressStep",
    "resultsSection",
    "errorSection",
    "errorMessage",
    "retryButton",
    "exportBar",
    "downloadReportBtn",
    "printReportBtn",
    "historySection",
    "historyList",
    "historyDisclosure",
    "clearHistoryBtn",
    "langToggle",
}

EXPECTED_SCRIPT_ORDER = [
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
