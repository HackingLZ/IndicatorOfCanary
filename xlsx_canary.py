#!/usr/bin/python3
"""
Extract and identify canary URLs from XLSX (Excel) files
Focuses on relationship files and metadata where canaries hide
"""

import json
import zipfile
import argparse
import os
from openpyxl import load_workbook
from datetime import datetime
from colorama import Fore, Style, init
import canary_config as config
import canary_utils as utils

init()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Extract canary URLs from XLSX files',
        epilog='Example: %(prog)s -i spreadsheet.xlsx -j output.json'
    )
    parser.add_argument("--input", "-i", required=True, help="Input XLSX file")
    parser.add_argument("--json", "-j", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--show-all", action="store_true",
                      help="Show all URLs including worksheet content (default: exclude worksheets)")
    return parser.parse_args()

def extract_xlsx_meta(xlsx_path):
    """
    Extract metadata from XLSX file
    
    Args:
        xlsx_path: Path to XLSX file
        
    Returns:
        Dictionary of metadata properties
    """
    try:
        wb = load_workbook(xlsx_path, data_only=True, read_only=True)
        props = wb.properties
        meta_data = {}
        
        properties_to_extract = [
            'title', 'subject', 'author', 'creator', 'keywords',
            'description', 'lastModifiedBy', 'modified', 'category',
            'contentStatus', 'revision', 'language', 'identifier',
            'version', 'lastPrinted', 'created'
        ]
        
        for prop in properties_to_extract:
            value = getattr(props, prop, None)
            if value is None or (isinstance(value, str) and not value.strip()):
                continue
            else:
                if isinstance(value, datetime):
                    value = value.isoformat()
                meta_data[prop] = value
        
        wb.close()
        return meta_data
        
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not extract metadata: {e}{Style.RESET_ALL}")
        return {}

def extract_urls_from_xlsx(xlsx_path, show_all=False, verbose=False):
    """
    Extract URLs from XLSX file components
    
    Args:
        xlsx_path: Path to XLSX file
        show_all: Include worksheet content URLs
        verbose: Print verbose output
        
    Returns:
        List of (url, location) tuples
    """
    urls = []
    
    try:
        with zipfile.ZipFile(xlsx_path) as xlsx:
            for file_info in xlsx.filelist:
                if file_info.is_dir():
                    continue
                
                filename = file_info.filename
                
                # Skip worksheet content and media unless requested
                if not show_all and utils.should_exclude_file(filename, config.XLSX_EXCLUDE_PATTERNS):
                    if verbose:
                        print(f"{Fore.CYAN}Skipping content file: {filename}{Style.RESET_ALL}")
                    continue
                
                # Extract URLs from file
                try:
                    content = xlsx.read(filename)
                    file_urls = utils.extract_urls_from_content(content, filename)
                    urls.extend(file_urls)
                    
                    if verbose and file_urls:
                        print(f"{Fore.GREEN}Found {len(file_urls)} URL(s) in: {filename}{Style.RESET_ALL}")
                        
                except Exception as e:
                    if verbose:
                        print(f"{Fore.YELLOW}Could not process {filename}: {e}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}Error reading XLSX file: {e}{Style.RESET_ALL}")
    
    return urls

def check_suspicious_metadata(meta_data):
    """
    Check metadata for suspicious indicators
    
    Args:
        meta_data: Metadata dictionary
        
    Returns:
        List of suspicious findings
    """
    findings = []
    
    # Check for bad authors
    for field in ['author', 'creator', 'lastModifiedBy']:
        if field in meta_data:
            value = str(meta_data[field]).lower()
            if value in config.BAD_AUTHORS:
                findings.append(f"Suspicious {field}: {meta_data[field]}")
    
    return findings

def main():
    args = parse_args()
    
    # Validate input file
    try:
        utils.validate_file_exists(args.input)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1
    
    # Extract metadata
    meta_data = extract_xlsx_meta(args.input)
    if meta_data:
        print(f"{Fore.CYAN}Metadata:{Style.RESET_ALL}")
        print(utils.format_metadata(meta_data))
        
        # Check for suspicious metadata
        suspicious = check_suspicious_metadata(meta_data)
        if suspicious:
            print(f"\n{Fore.YELLOW}Suspicious metadata:{Style.RESET_ALL}")
            for finding in suspicious:
                print(f"  {Fore.YELLOW}⚠ {finding}{Style.RESET_ALL}")
    
    # Extract URLs
    print(f"\n{Fore.CYAN}URL(s):{Style.RESET_ALL}")
    urls = extract_urls_from_xlsx(args.input, args.show_all, args.verbose)
    
    # Filter URLs
    filtered_urls = utils.filter_urls(urls)
    
    # Print colored URLs
    if filtered_urls:
        utils.print_colored_urls(filtered_urls)
    else:
        print(f"{Fore.GREEN}No suspicious URLs found{Style.RESET_ALL}")
    
    # Export to JSON if requested
    if args.json:
        md5, sha1, sha256 = utils.hash_file(args.input)
        data_to_export = {
            "meta": meta_data,
            "urls": [{"url": url, "location": location} for url, location in filtered_urls],
            "hashes": {
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256
            },
            "total_urls_found": len(urls),
            "suspicious_urls": len(filtered_urls),
            "suspicious_metadata": check_suspicious_metadata(meta_data)
        }
        
        utils.write_to_json(args.json, args.input, data_to_export)
        print(f"\n{Fore.GREEN}Results written to: {args.json}{Style.RESET_ALL}")
    
    # Summary
    if args.verbose:
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Total URLs found: {len(urls)}")
        print(f"  After filtering: {len(filtered_urls)}")
        
        # Check for known canaries
        known_canaries = [url for url, _ in filtered_urls 
                         if utils.url_in_list(url, config.ALERT_DOMAINS)]
        if known_canaries:
            print(f"  {Fore.RED}Known canaries detected: {len(known_canaries)}{Style.RESET_ALL}")
    
    return 0

if __name__ == "__main__":
    exit(main())