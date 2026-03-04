"""
Validation utilities
"""

import os
from typing import Tuple


ALLOWED_EXTENSIONS = {'eml', 'msg'}


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_email_file(file_data: bytes, filename: str) -> Tuple[bool, str]:
    """
    Validate email file content

    Args:
        file_data: File content as bytes
        filename: Original filename

    Returns:
        (is_valid, error_message)
    """
    # Check if file is empty
    if not file_data or len(file_data) == 0:
        return False, "File is empty"

    # Check minimum size (at least a few bytes)
    if len(file_data) < 10:
        return False, "File is too small to be a valid email"

    # Check maximum size (50MB)
    max_size = 50 * 1024 * 1024
    if len(file_data) > max_size:
        return False, f"File exceeds maximum size of 50MB"

    # Basic format validation
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

    if ext == 'eml':
        # EML files should contain email headers
        try:
            content = file_data[:1000].decode('utf-8', errors='ignore')
            # Check for common email headers
            required_indicators = ['From:', 'To:', 'Subject:', 'Date:']
            if not any(indicator in content for indicator in required_indicators):
                return False, "File does not appear to be a valid EML file"
        except Exception:
            return False, "Unable to read EML file content"

    elif ext == 'msg':
        # MSG files should have OLE signature
        if not file_data.startswith(b"\xD0\xCF\x11\xE0"):
            return False, "File does not appear to be a valid MSG file"

    return True, ""
