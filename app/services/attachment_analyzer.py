"""
Attachment Analyzer Service
Analyzes email attachments for suspicious characteristics
"""

from typing import List, Dict, Any
import os


class AttachmentAnalyzerService:
    """Service for analyzing email attachments"""

    # Dangerous file extensions.
    #
    # This list was a 2010-era set that omitted the vectors actually in use.
    # Most notably `.lnk` — currently the single most common loader delivery
    # format — scored zero, as did `.svg` (which renders as a page and can
    # carry script) and `.url`/`.scf`/`.settingcontent-ms`. An attachment whose
    # extension was absent got issues == [], severity 'low', is_suspicious
    # False, and therefore contributed nothing to the risk score.
    EXECUTABLE_EXTENSIONS = {
        'exe', 'scr', 'com', 'bat', 'cmd', 'pif', 'vbs', 'vbe', 'js', 'jse',
        'jar', 'msi', 'msix', 'appx', 'app', 'deb', 'rpm', 'run', 'ps1',
        'psm1', 'ps1xml', 'cpl', 'msc', 'reg', 'sct', 'jnlp', 'gadget',
        'inf', 'ins', 'isp', 'job', 'ws', 'wsc', 'pyz', 'pyzw', 'apk', 'dmg',
    }

    # Shortcut / handler formats. Not executables themselves, but each one
    # causes something else to execute or fetch when opened.
    SHORTCUT_EXTENSIONS = {
        'lnk', 'url', 'scf', 'website', 'settingcontent-ms', 'library-ms',
        'searchconnector-ms', 'diagcab', 'appref-ms', 'desktop',
    }

    # Office documents that can contain macros or external code
    MACRO_EXTENSIONS = {
        'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam',
        'xll', 'wll', 'xlsb', 'slk', 'iqy',
        'doc', 'xls', 'ppt'  # Legacy formats can also have macros
    }

    # Archive and disk-image formats that hide their contents from scanners and
    # bypass mark-of-the-web.
    ARCHIVE_EXTENSIONS = {
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img',
        'vhd', 'vhdx', 'cab', 'ace', 'arj', 'lzh', 'wim', 'wsb',
    }

    # Files that render as, or contain, active markup.
    SCRIPT_EXTENSIONS = {
        'html', 'htm', 'hta', 'xhtml', 'mht', 'mhtml', 'svg', 'chm',
        'vbs', 'js', 'jse', 'wsf', 'wsh', 'xsl', 'xslt', 'shtml',
    }

    # Extensions a user can reasonably expect to receive. Anything outside this
    # set, and outside the deny-lists above, is treated as unrecognised rather
    # than assumed benign — a deny-list alone can only ever be as current as the
    # day it was written.
    COMMON_BENIGN_EXTENSIONS = {
        'pdf', 'txt', 'rtf', 'csv', 'log', 'md',
        'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'dotx', 'xltx', 'potx',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp', 'heic', 'ico',
        'mp3', 'wav', 'ogg', 'flac', 'm4a', 'mp4', 'mov', 'avi', 'mkv', 'webm',
        'eml', 'msg', 'ics', 'vcf', 'json', 'xml', 'yaml', 'yml',
    }

    def __init__(self):
        pass

    def analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze all attachments

        Args:
            attachments: List of attachment info from parser

        Returns:
            Analysis results including suspicious count
        """
        if not attachments:
            return {
                'total_count': 0,
                'suspicious_count': 0,
                'attachments': []
            }

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
            'attachments': analyzed
        }

    def analyze_single_attachment(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single attachment"""
        filename = attachment.get('filename', '')
        ext = attachment.get('extension', '').lower()
        content_type = attachment.get('content_type', '')
        size = attachment.get('size', 0)

        issues = []
        severity = 'low'

        # Check for executable files
        if ext in self.EXECUTABLE_EXTENSIONS:
            issues.append('executable_file')
            severity = 'critical'

        # Shortcut/handler files execute or fetch something else when opened.
        elif ext in self.SHORTCUT_EXTENSIONS:
            issues.append('shortcut_file')
            severity = 'critical'

        # Check for macro-enabled documents
        elif ext in self.MACRO_EXTENSIONS:
            issues.append('possible_macro_document')
            severity = 'high'

        # Check for script files
        elif ext in self.SCRIPT_EXTENSIONS:
            issues.append('script_file')
            severity = 'high'

        # Check for archives
        elif ext in self.ARCHIVE_EXTENSIONS:
            issues.append('archive_file')
            severity = 'medium'

        # Anything not recognised at all. A deny-list is only current as of the
        # day it was written, so an unknown extension is reported rather than
        # assumed safe.
        elif ext and ext not in self.COMMON_BENIGN_EXTENSIONS:
            issues.append('unrecognised_extension')
            severity = 'medium'

        # No usable extension on a binary payload — often the result of a
        # trailing dot or a name crafted to defeat extension parsing.
        elif not ext:
            issues.append('missing_extension')
            severity = 'medium'

        # Check for double extensions (e.g., invoice.pdf.exe)
        # Use rsplit to correctly isolate the two rightmost extensions
        parts = filename.rsplit('.', 2)
        if len(parts) == 3:
            # parts = ['invoice', 'pdf', 'exe'] — check second-to-last
            if parts[-2].lower() in {'pdf', 'doc', 'xls', 'jpg', 'png', 'txt'}:
                issues.append('double_extension')
                severity = 'critical'

        # Check for suspicious naming patterns
        suspicious_keywords = [
            'invoice', 'receipt', 'payment', 'statement', 'urgent', 'important',
            'secure', 'verify', 'confirm', 'update', 'password', 'account'
        ]
        filename_lower = filename.lower()
        if any(keyword in filename_lower for keyword in suspicious_keywords):
            issues.append('suspicious_filename')

        # Check for very small executables (packers/droppers)
        if ext in self.EXECUTABLE_EXTENSIONS and size > 0 and size < 10240:  # < 10KB
            issues.append('unusually_small_executable')
            severity = 'critical'

        # The file's actual leading bytes contradict what it is called. An
        # .exe named holiday.jpg passes every name-based check ever written;
        # a disguise is a stronger signal than either fact on its own.
        mismatch = attachment.get('content_mismatch')
        if mismatch:
            issues.append(f'content_mismatch:{mismatch}')
            if mismatch in ('pe_executable', 'elf_executable', 'macho_executable',
                            'windows_shortcut'):
                severity = 'critical'
            else:
                severity = self._escalate(severity, 'high')

        # Check for very large files (potential data exfiltration)
        if size > 50 * 1024 * 1024:  # > 50MB
            issues.append('unusually_large_file')

        # Check for hidden extensions (spaces before extension)
        if filename.endswith(' ' + ext):
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
            'is_suspicious': len(issues) > 0
        }

    @staticmethod
    def _escalate(current: str, candidate: str) -> str:
        """Raise a severity, never lower it."""
        order = ['low', 'medium', 'high', 'critical']
        if current not in order:
            return candidate
        return candidate if order.index(candidate) > order.index(current) else current

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
