#!/usr/bin/python3
"""
Extract and identify canary URLs from PPTX (PowerPoint) files
Focuses on relationship files and metadata where canaries hide
"""

import json
import zipfile
import argparse
import os
from pptx import Presentation
from datetime import datetime
from colorama import Fore, Style, init
import canary_config as config
import canary_utils as utils

init()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Extract canary URLs from PPTX files',
        epilog='Example: %(prog)s -i presentation.pptx -j output.json'
    )
    parser.add_argument("--input", "-i", required=True, help="Input PPTX file")
    parser.add_argument("--json", "-j", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--show-all", action="store_true",
                      help="Show all URLs including slide content (default: exclude slides)")
    return parser.parse_args()

def extract_pptx_meta(pptx_path):
    """
    Extract metadata from PPTX file
    
    Args:
        pptx_path: Path to PPTX file
        
    Returns:
        Dictionary of metadata properties
    """
    try:
        prs = Presentation(pptx_path)
        properties = prs.core_properties
        
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

def extract_urls_from_pptx(pptx_path, show_all=False, verbose=False):
    """
    Extract URLs from PPTX file components
    
    Args:
        pptx_path: Path to PPTX file
        show_all: Include slide content URLs
        verbose: Print verbose output
        
    Returns:
        List of (url, location) tuples
    """
    urls = []
    
    try:
        with zipfile.ZipFile(pptx_path) as pptx:
            for file_info in pptx.filelist:
                if file_info.is_dir():
                    continue
                
                filename = file_info.filename
                
                # Only process XML and relationship files
                if not (filename.endswith('.xml') or filename.endswith('.rels')):
                    if verbose:
                        print(f"{Fore.CYAN}Skipping non-XML file: {filename}{Style.RESET_ALL}")
                    continue
                
                # Skip slide content and media unless requested
                if not show_all and utils.should_exclude_file(filename, config.PPTX_EXCLUDE_PATTERNS):
                    if verbose:
                        print(f"{Fore.CYAN}Skipping content file: {filename}{Style.RESET_ALL}")
                    continue
                
                # Extract URLs from file
                try:
                    content = pptx.read(filename)
                    file_urls = utils.extract_urls_from_content(content, filename)
                    urls.extend(file_urls)
                    
                    if verbose and file_urls:
                        print(f"{Fore.GREEN}Found {len(file_urls)} URL(s) in: {filename}{Style.RESET_ALL}")
                        
                except Exception as e:
                    if verbose:
                        print(f"{Fore.YELLOW}Could not process {filename}: {e}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}Error reading PPTX file: {e}{Style.RESET_ALL}")
    
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
    for field in ['author', 'last_modified_by']:
        if field in meta_data:
            value = str(meta_data[field]).lower()
            if value in config.BAD_AUTHORS:
                findings.append(f"Suspicious {field}: {meta_data[field]}")
    
    # Check for missing or suspicious dates
    if 'created' in meta_data and 'modified' in meta_data:
        created = meta_data['created']
        modified = meta_data['modified']
        if created == modified:
            findings.append("Created and modified timestamps are identical")
    
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
    meta_data = extract_pptx_meta(args.input)
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
    urls = extract_urls_from_pptx(args.input, args.show_all, args.verbose)
    
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