"""
Attachment Analyzer Service
Analyzes email attachments for suspicious characteristics
"""

from typing import List, Dict, Any
import os


class AttachmentAnalyzerService:
    """Service for analyzing email attachments"""

    # Dangerous file extensions
    EXECUTABLE_EXTENSIONS = {
        'exe', 'scr', 'com', 'bat', 'cmd', 'pif', 'vbs', 'js', 'jar',
        'msi', 'app', 'deb', 'rpm', 'run', 'ps1', 'psm1'
    }

    # Office documents that can contain macros
    MACRO_EXTENSIONS = {
        'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm',
        'doc', 'xls', 'ppt'  # Legacy formats can also have macros
    }

    # Archive formats that could hide malware
    ARCHIVE_EXTENSIONS = {
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img'
    }

    # HTML/Script files
    SCRIPT_EXTENSIONS = {
        'html', 'htm', 'hta', 'vbs', 'js', 'jse', 'wsf', 'wsh'
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

        # Check for double extensions (e.g., invoice.pdf.exe)
        parts = filename.split('.')
        if len(parts) > 2:
            # Check if second-to-last extension is a common document type
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

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
