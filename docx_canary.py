#!/usr/bin/python3
"""
Extract and identify canary URLs from DOCX files
Focuses on relationship files and metadata where canaries hide
"""

import json
import zipfile
import argparse
import os
from docx import Document
from datetime import datetime
from colorama import Fore, Style, init
import canary_config as config
import canary_utils as utils

init()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Extract canary URLs from DOCX files',
        epilog='Example: %(prog)s -i document.docx -j output.json'
    )
    parser.add_argument("--input", "-i", required=True, help="Input DOCX file")
    parser.add_argument("--json", "-j", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--show-all", action="store_true", 
                      help="Show all URLs including body content (default: exclude body)")
    return parser.parse_args()

def extract_docx_meta(docx_path):
    """
    Extract metadata from DOCX file
    
    Args:
        docx_path: Path to DOCX file
        
    Returns:
        Dictionary of metadata properties
    """
    try:
        doc = Document(docx_path)
        properties = doc.core_properties
        
        # Get all properties
        meta_data = {}
        for prop in dir(properties):
            if not prop.startswith('_') and not callable(getattr(properties, prop)):
                value = getattr(properties, prop)
                if value:
                    if isinstance(value, datetime):
                        meta_data[prop] = value.isoformat()
                    else:
                        meta_data[prop] = value
        
        return meta_data
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not extract metadata: {e}{Style.RESET_ALL}")
        return {}

def extract_urls_from_docx(docx_path, show_all=False, verbose=False):
    """
    Extract URLs from DOCX file components
    
    Args:
        docx_path: Path to DOCX file
        show_all: Include body content URLs
        verbose: Print verbose output
        
    Returns:
        List of (url, location) tuples
    """
    urls = []
    
    try:
        with zipfile.ZipFile(docx_path) as doc:
            for file_info in doc.filelist:
                if file_info.is_dir():
                    continue
                
                filename = file_info.filename
                
                # Skip body content unless requested
                if not show_all and utils.should_exclude_file(filename, config.DOCX_EXCLUDE_FILES):
                    if verbose:
                        print(f"{Fore.CYAN}Skipping body content: {filename}{Style.RESET_ALL}")
                    continue
                
                # Extract URLs from file
                try:
                    content = doc.read(filename)
                    file_urls = utils.extract_urls_from_content(content, filename)
                    urls.extend(file_urls)
                    
                    if verbose and file_urls:
                        print(f"{Fore.GREEN}Found {len(file_urls)} URL(s) in: {filename}{Style.RESET_ALL}")
                        
                except Exception as e:
                    if verbose:
                        print(f"{Fore.YELLOW}Could not process {filename}: {e}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}Error reading DOCX file: {e}{Style.RESET_ALL}")
    
    return urls

def main():
    args = parse_args()
    
    # Validate input file
    try:
        utils.validate_file_exists(args.input)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1
    
    # Extract metadata
    meta_data = extract_docx_meta(args.input)
    if meta_data:
        print(f"{Fore.CYAN}Metadata:{Style.RESET_ALL}")
        print(utils.format_metadata(meta_data))
    
    # Extract URLs
    print(f"\n{Fore.CYAN}URL(s):{Style.RESET_ALL}")
    urls = extract_urls_from_docx(args.input, args.show_all, args.verbose)
    
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
            "suspicious_urls": len(filtered_urls)
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