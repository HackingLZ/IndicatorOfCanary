#!/usr/bin/python3
"""
Shared configuration for Indicator of Canary tools
Contains common domains, patterns, and constants used across all scripts
"""

import re

# Domains to ignore (legitimate/expected domains)
IGNORE_DOMAINS = {
    'purl.org',
    'microsoft.com',
    'openxmlformats.org',
    'w3.org',
    'dublincore.org',
    'publicdomainpictures.net'
}

# Known canary provider domains (high confidence indicators)
ALERT_DOMAINS = {
    'internalcanarytokendomain.org',
    'canarytokens.com',
    'canarytokens.net',
    'allsafelink.com', 
    'whiteclouddrive.com',
    'ittftm.com'  # Found in sample data
}

# Suspicious document authors
BAD_AUTHORS = {
    'openpyxl',
    'AAAAAAAAAAAAAAAA'  # Found in sample data
}

# Known canary AWS Account IDs
KNOWN_CANARY_ACCOUNTS = {
    '706555150306',
    '992382622183'
}

# Known canary IP addresses
KNOWN_CANARY_IPS = {
    '52.18.63.80'
}

# URL pattern for extraction
URL_PATTERN = re.compile(r"https?://[\w.-]+(?::\d+)?(?:[/\w .-]*)?", re.IGNORECASE)

# File exclusions for different document types
DOCX_EXCLUDE_FILES = {
    'word/document.xml',  # Main body content
    'word/comments.xml',   # Comments
    'word/footnotes.xml',  # Footnotes
    'word/endnotes.xml'    # Endnotes
}

XLSX_EXCLUDE_PATTERNS = {
    'xl/worksheets/',      # Worksheet content
    'xl/sharedStrings.xml', # Shared strings (cell content)
    'xl/media/'            # Embedded media
}

PPTX_EXCLUDE_PATTERNS = {
    'ppt/slides/slide',    # Slide content
    'ppt/notesSlides/',    # Notes content
    'ppt/media/'           # Embedded media
}

# Output colors configuration
COLOR_CONFIG = {
    'alert': 'RED',       # Known canary domains
    'suspicious': 'YELLOW', # Unknown/suspicious domains
    'info': 'GREEN'       # Informational
}