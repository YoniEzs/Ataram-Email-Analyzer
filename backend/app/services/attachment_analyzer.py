"""
Attachment Analyzer Service
Analyzes email attachments for suspicious characteristics
"""

import hashlib
import io
import logging
import os
import zipfile
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)

# Unicode bidirectional control characters. U+202E (right-to-left override)
# makes "annexe_‮fdp.exe" display as "annexe_exe.pdf"; legitimate
# filenames essentially never contain any of these.
_BIDI_CONTROL_CHARS = frozenset(
    '\u200e\u200f'                               # LRM, RLM
    '\u202a\u202b\u202c\u202d\u202e'  # LRE, RLE, PDF, LRO, RLO
    '\u2066\u2067\u2068\u2069'        # LRI, RLI, FSI, PDI
)


class AttachmentAnalyzerService:
    """Service for analyzing email attachments"""

    EXECUTABLE_EXTENSIONS = {
        # Classic Windows executables
        'exe', 'scr', 'com', 'bat', 'cmd', 'pif',
        # Script formats
        'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
        # Packages / installers
        'msi', 'msp', 'jar', 'deb', 'rpm', 'run', 'pkg', 'dmg',
        # PowerShell
        'ps1', 'psm1', 'psd1', 'ps1xml',
        # Shell
        'sh', 'bash', 'zsh', 'ksh',
        # Windows extras (often used in living-off-the-land attacks)
        'lnk',   # Windows shortcut — common dropper vector
        'reg',   # Registry file — can add persistence keys
        'inf',   # Setup information — can auto-run
        'cpl',   # Control Panel applet
        'app',   # macOS application bundle
    }

    # Office documents that can contain macros
    MACRO_EXTENSIONS = {
        'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm',
        'doc', 'xls', 'ppt',  # Legacy formats may also contain macros
        'xlsb',               # Binary workbook — harder to inspect
    }

    # HTML/Script files
    SCRIPT_EXTENSIONS = {
        'html', 'htm',
        'hta',   # HTML Application — runs with elevated privileges in IE/Windows
        'svg',   # Can embed JavaScript
    }

    # Archive formats that can hide payloads
    ARCHIVE_EXTENSIONS = {
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img',
        'cab',  # Windows Cabinet — used in dropper chains
    }

    # Magic-byte signatures for formats attackers commonly masquerade as.
    # Office OOXML formats are zip containers; legacy Office is OLE.
    MAGIC_SIGNATURES = {
        'pdf': (b'%PDF',),
        'png': (b'\x89PNG',),
        'jpg': (b'\xff\xd8\xff',),
        'jpeg': (b'\xff\xd8\xff',),
        'gif': (b'GIF8',),
        'zip': (b'PK\x03\x04', b'PK\x05\x06'),
        'docx': (b'PK\x03\x04',),
        'xlsx': (b'PK\x03\x04',),
        'pptx': (b'PK\x03\x04',),
        'doc': (b'\xd0\xcf\x11\xe0',),
        'xls': (b'\xd0\xcf\x11\xe0',),
        'ppt': (b'\xd0\xcf\x11\xe0',),
        'rar': (b'Rar!',),
        '7z': (b'7z\xbc\xaf',),
        'gz': (b'\x1f\x8b',),
    }

    # Content signatures that mark a file as executable no matter what the
    # filename claims.
    EXECUTABLE_MAGIC = (
        b'MZ',                # Windows PE
        b'\x7fELF',           # Linux ELF
        b'#!',                # script with shebang
        b'\xfe\xed\xfa\xce',  # Mach-O 32-bit
        b'\xfe\xed\xfa\xcf',  # Mach-O 64-bit
        b'\xcf\xfa\xed\xfe',  # Mach-O little-endian
    )

    _MAX_ARCHIVE_MEMBERS = 100

    def __init__(self):
        pass

    def analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze all attachments."""
        if not attachments:
            return {'total_count': 0, 'suspicious_count': 0, 'attachments': []}

        analyzed = []
        suspicious_count = 0

        for attachment in attachments:
            result = self.analyze_single_attachment(attachment)
            analyzed.append(result)
            if result['is_suspicious']:
                suspicious_count += 1

        return {
            'total_count': len(attachments),
            'suspicious_count': suspicious_count,
            'attachments': analyzed,
        }

    def analyze_single_attachment(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single attachment."""
        filename = attachment.get('filename', '')
        # Strip whitespace so "invoice.exe " can't dodge the extension checks.
        raw_ext = attachment.get('extension', '')
        ext = raw_ext.strip().lower()
        content_type = attachment.get('content_type', '')
        size = attachment.get('size', 0)

        issues = []
        severity = 'low'

        def escalate(new_severity: str) -> None:
            nonlocal severity
            rank = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            if rank[new_severity] > rank[severity]:
                severity = new_severity

        if ext in self.EXECUTABLE_EXTENSIONS:
            issues.append('executable_file')
            escalate('critical')
        elif ext in self.MACRO_EXTENSIONS:
            issues.append('possible_macro_document')
            escalate('high')
        elif ext in self.SCRIPT_EXTENSIONS:
            issues.append('script_file')
            escalate('high')
        elif ext in self.ARCHIVE_EXTENSIONS:
            issues.append('archive_file')
            escalate('medium')

        # Double-extension: e.g. "invoice.pdf.exe"
        # Check if ANY non-last extension is a benign-looking document type
        # (strip so "invoice.pdf    .exe" padding is caught too)
        parts = filename.split('.')
        if len(parts) > 2:
            benign_decoys = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg',
                             'png', 'gif', 'txt', 'csv', 'mp4', 'mp3'}
            if parts[-2].strip().lower() in benign_decoys:
                issues.append('double_extension')
                escalate('critical')

        suspicious_keywords = [
            'invoice', 'receipt', 'payment', 'statement', 'urgent', 'important',
            'secure', 'verify', 'confirm', 'update', 'password', 'account',
        ]
        if any(kw in filename.lower() for kw in suspicious_keywords):
            issues.append('suspicious_filename')

        # Very small executable (packer/dropper/stub)
        if ext in self.EXECUTABLE_EXTENSIONS and 0 < size < 10_240:
            issues.append('unusually_small_executable')
            escalate('critical')

        if size > 50 * 1024 * 1024:
            issues.append('unusually_large_file')

        # Hidden extension via whitespace around the real extension,
        # e.g. "invoice.exe " or "report.pdf .exe"
        if filename != filename.strip() or raw_ext != raw_ext.strip():
            issues.append('hidden_extension')
            escalate('high')

        # Bidi control characters visually reverse the displayed extension
        if any(ch in _BIDI_CONTROL_CHARS for ch in filename):
            issues.append('bidi_spoofed_filename')
            escalate('critical')

        # Content inspection when raw bytes are available
        data = attachment.get('data') or b''
        sha256 = hashlib.sha256(data).hexdigest() if data else None
        if data:
            self._inspect_content(data, ext, issues, escalate)

        return {
            'filename': filename,
            'extension': ext,
            'content_type': content_type,
            'size': size,
            'size_formatted': self._format_size(size),
            'sha256': sha256,
            'issues': issues,
            'severity': severity,
            'is_suspicious': len(issues) > 0,
        }

    def _inspect_content(
        self, data: bytes, ext: str, issues: List[str], escalate: Callable[[str], None]
    ) -> None:
        """Compare actual file content against the claimed extension."""
        # Executable content hiding behind a non-executable name
        if data.startswith(self.EXECUTABLE_MAGIC) and ext not in self.EXECUTABLE_EXTENSIONS:
            issues.append('executable_content_mismatch')
            escalate('critical')

        # Claimed a known format but the magic bytes disagree
        expected = self.MAGIC_SIGNATURES.get(ext)
        if expected and len(data) >= 8 and not data.startswith(expected):
            issues.append('content_type_mismatch')
            escalate('high')

        # Peek inside zip containers (plain .zip only — OOXML documents are
        # also zips but their members are document internals, not payloads)
        if ext == 'zip' and data.startswith(b'PK'):
            self._inspect_zip(data, issues, escalate)

    def _inspect_zip(
        self, data: bytes, issues: List[str], escalate: Callable[[str], None]
    ) -> None:
        """List zip members (no extraction) for hidden executables."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                encrypted = False
                has_executable = False
                for info in zf.infolist()[:self._MAX_ARCHIVE_MEMBERS]:
                    if info.flag_bits & 0x1:
                        encrypted = True
                    member_ext = os.path.splitext(info.filename.lower())[1].lstrip('.')
                    if member_ext.strip() in self.EXECUTABLE_EXTENSIONS:
                        has_executable = True
                if has_executable:
                    issues.append('archive_contains_executable')
                    escalate('critical')
                if encrypted:
                    # Password-protected zips are a standard AV-evasion trick
                    issues.append('encrypted_archive')
                    escalate('high')
        except Exception as e:
            logger.debug(f"[AttachmentAnalyzerService] zip inspection failed: {e}")
            issues.append('corrupt_or_unreadable_archive')

    def _format_size(self, size: float) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
