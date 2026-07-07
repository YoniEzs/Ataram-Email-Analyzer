"""
Attachment Analyzer Service
Analyzes email attachments for suspicious characteristics
"""

from typing import List, Dict, Any


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
        ext = attachment.get('extension', '').lower()
        content_type = attachment.get('content_type', '')
        size = attachment.get('size', 0)

        issues = []
        severity = 'low'

        if ext in self.EXECUTABLE_EXTENSIONS:
            issues.append('executable_file')
            severity = 'critical'
        elif ext in self.MACRO_EXTENSIONS:
            issues.append('possible_macro_document')
            severity = 'high'
        elif ext in self.SCRIPT_EXTENSIONS:
            issues.append('script_file')
            severity = 'high'
        elif ext in self.ARCHIVE_EXTENSIONS:
            issues.append('archive_file')
            severity = 'medium'

        # Double-extension: e.g. "invoice.pdf.exe"
        # Check if ANY non-last extension is a benign-looking document type
        parts = filename.split('.')
        if len(parts) > 2:
            benign_decoys = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg',
                             'png', 'gif', 'txt', 'csv', 'mp4', 'mp3'}
            if parts[-2].lower() in benign_decoys:
                issues.append('double_extension')
                severity = 'critical'

        suspicious_keywords = [
            'invoice', 'receipt', 'payment', 'statement', 'urgent', 'important',
            'secure', 'verify', 'confirm', 'update', 'password', 'account',
        ]
        if any(kw in filename.lower() for kw in suspicious_keywords):
            issues.append('suspicious_filename')

        # Very small executable (packer/dropper/stub)
        if ext in self.EXECUTABLE_EXTENSIONS and 0 < size < 10_240:
            issues.append('unusually_small_executable')
            severity = 'critical'

        if size > 50 * 1024 * 1024:
            issues.append('unusually_large_file')

        # Hidden extension via trailing space before real extension
        if filename.rstrip().endswith('.' + ext) and filename != filename.rstrip():
            issues.append('hidden_extension')
            severity = 'high'

        return {
            'filename': filename,
            'extension': ext,
            'content_type': content_type,
            'size': size,
            'size_formatted': self._format_size(size),
            'issues': issues,
            'severity': severity,
            'is_suspicious': len(issues) > 0,
        }

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
