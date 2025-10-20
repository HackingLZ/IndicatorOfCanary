#!/usr/bin/python3
"""
Shared utilities for Indicator of Canary tools
Contains common functions used across all scripts
"""

import os
import json
import hashlib
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init
import canary_config as config

# Initialize colorama
init()

def safe_decode(content):
    """
    Safely decode byte content to string with proper error handling
    
    Args:
        content: Byte content to decode
        
    Returns:
        Decoded string or None if binary file
    """
    try:
        return content.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return content.decode('utf-8', errors='ignore')
        except:
            return None

def url_in_list(url, lst):
    """
    Check if URL hostname matches any domain in the list
    
    Args:
        url: URL to check
        lst: List/set of domains to check against
        
    Returns:
        True if URL matches any domain in list
    """
    try:
        hostname = urlparse(url).hostname
        if hostname:
            return any(hostname.endswith(domain) for domain in lst)
    except:
        pass
    return False

def extract_urls_from_content(content, filename):
    """
    Extract URLs from file content
    
    Args:
        content: File content (bytes)
        filename: Name of the file for context
        
    Returns:
        List of (url, filename) tuples
    """
    text = safe_decode(content)
    if text is None:
        return []
    
    urls = config.URL_PATTERN.findall(text)
    return [(url, filename) for url in urls]

def filter_urls(urls, ignore_list=None):
    """
    Filter out URLs from ignore list
    
    Args:
        urls: List of (url, filename) tuples
        ignore_list: Domains to ignore (defaults to config.IGNORE_DOMAINS)
        
    Returns:
        Filtered list of URLs
    """
    if ignore_list is None:
        ignore_list = config.IGNORE_DOMAINS
    
    return [url for url in urls if not url_in_list(url[0], ignore_list)]

def print_colored_urls(urls, alert_list=None):
    """
    Print URLs with color coding based on threat level
    
    Args:
        urls: List of (url, location) tuples
        alert_list: Known bad domains (defaults to config.ALERT_DOMAINS)
    """
    if alert_list is None:
        alert_list = config.ALERT_DOMAINS
    
    for url, location in urls:
        if url_in_list(url, alert_list):
            color = Fore.RED
        else:
            color = Fore.YELLOW
        print(f"{color}{url} - {location}{Style.RESET_ALL}")

def hash_file(file_path):
    """
    Calculate MD5 and SHA1 hashes of a file
    
    Args:
        file_path: Path to file to hash
        
    Returns:
        Tuple of (md5, sha1) hashes as hex strings
    """
    with open(file_path, "rb") as f:
        file_content = f.read()
    
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    sha256 = hashlib.sha256(file_content).hexdigest()
    
    return md5, sha1, sha256

def write_to_json(output_path, file_name, data):
    """
    Write results to JSON file
    
    Args:
        output_path: Path to output JSON file
        file_name: Name of the analyzed file
        data: Data dictionary to write
    """
    # Use proper path functions
    if file_name:
        file_name = os.path.basename(file_name)
    
    with open(output_path, "w") as f:
        json.dump({file_name: data}, f, indent=4)

def format_metadata(meta_data):
    """
    Format metadata dictionary for display
    
    Args:
        meta_data: Dictionary of metadata
        
    Returns:
        Formatted string for display
    """
    lines = []
    for prop, value in meta_data.items():
        if isinstance(value, datetime):
            value = value.isoformat()
        
        # Highlight suspicious authors
        if prop in ['author', 'creator', 'lastModifiedBy'] and value:
            if str(value).lower() in config.BAD_AUTHORS:
                lines.append(f"{Fore.RED}{prop}: {value}{Style.RESET_ALL}")
            else:
                lines.append(f"{prop}: {value}")
        else:
            lines.append(f"{prop}: {value}")
    
    return '\n'.join(lines)

def should_exclude_file(filename, exclude_patterns):
    """
    Check if file should be excluded based on patterns
    
    Args:
        filename: File path/name to check
        exclude_patterns: Set of patterns to exclude
        
    Returns:
        True if file should be excluded
    """
    for pattern in exclude_patterns:
        if pattern.endswith('/'):
            # Directory pattern
            if filename.startswith(pattern):
                return True
        else:
            # Exact file match
            if filename == pattern:
                return True
            # Pattern match for slide files etc
            if pattern in filename:
                return True
    return False

def get_file_basename(file_path):
    """
    Cross-platform safe way to get filename from path
    
    Args:
        file_path: Full file path
        
    Returns:
        Base filename
    """
    return os.path.basename(file_path)

def validate_file_exists(file_path):
    """
    Validate that a file exists and is readable
    
    Args:
        file_path: Path to validate
        
    Returns:
        True if file exists and is readable
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file isn't readable
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"File is not readable: {file_path}")
    
    return True