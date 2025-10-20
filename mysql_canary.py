#!/usr/bin/python3
"""
Extract and identify canary URLs from MySQL dump files
Searches for both base64-encoded and plaintext URLs in SQL dumps
"""

import argparse
import base64
import re
import os
from colorama import Fore, Style, init
import canary_config as config
import canary_utils as utils

init()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Extract MySQL dump canaries (b64/plaintext)",
        epilog='Example: %(prog)s -i dump.sql -j output.json'
    )
    parser.add_argument("--input", "-i", required=True, help="Path to the input SQL dump file")
    parser.add_argument("--json", "-j", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser.parse_args()

def highlight_and_append_text(text, append_text, alert_list=None):
    """
    Format text with color coding and append context
    
    Args:
        text: The URL/text to format
        append_text: Context to append
        alert_list: Known bad domains
        
    Returns:
        Formatted string with color codes
    """
    if alert_list is None:
        alert_list = config.ALERT_DOMAINS
    
    if utils.url_in_list(text, alert_list):
        return f"{Fore.RED}{text}{Style.RESET_ALL} - {append_text}"
    else:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL} - {append_text}"

def extract_and_process_data(sql_dump_path, verbose=False):
    """
    Extract URLs from MySQL dump file
    
    Args:
        sql_dump_path: Path to SQL dump file
        verbose: Print verbose output
        
    Returns:
        List of (url, context) tuples
    """
    # Regex patterns for different types of URLs
    set_base64_pattern = re.compile(r"SET\s+@\w+\s*=\s*'([^']+)'")
    set_master_host_pattern = re.compile(r"MASTER_HOST\s*=\s*'([^']+)'", re.IGNORECASE)
    
    # Additional patterns for URLs in data
    insert_url_pattern = re.compile(r"INSERT\s+INTO\s+\w+.*?'(https?://[^']+)'", re.IGNORECASE)
    
    found_urls = []
    line_number = 0
    
    try:
        with open(sql_dump_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line_number += 1
                line = line.strip()
                
                if not line:
                    continue
                
                # Check for base64-encoded data in SET statements
                base64_match = set_base64_pattern.search(line)
                if base64_match:
                    base64_value = base64_match.group(1)
                    try:
                        decoded_data = base64.b64decode(base64_value).decode('utf-8', errors='ignore')
                        
                        # Look for URLs in decoded data
                        urls_in_decoded = config.URL_PATTERN.findall(decoded_data)
                        for url in urls_in_decoded:
                            context = f"BASE64 (line {line_number})"
                            found_urls.append((url, context))
                            
                            if verbose:
                                print(f"{Fore.GREEN}Found in base64: {url}{Style.RESET_ALL}")
                                
                    except (base64.binascii.Error, UnicodeDecodeError):
                        # Not valid base64 or contains binary data
                        if verbose:
                            print(f"{Fore.CYAN}Skipped invalid base64 on line {line_number}{Style.RESET_ALL}")
                        continue
                
                # Check for MASTER_HOST patterns
                master_host_match = set_master_host_pattern.search(line)
                if master_host_match:
                    domain_name = master_host_match.group(1)
                    # Construct URL if it's just a domain
                    if not domain_name.startswith('http'):
                        domain_name = f"http://{domain_name}"
                    
                    context = f"CLEARTEXT MASTER_HOST (line {line_number})"
                    found_urls.append((domain_name, context))
                    
                    if verbose:
                        print(f"{Fore.GREEN}Found master host: {domain_name}{Style.RESET_ALL}")
                
                # Check for URLs in INSERT statements
                insert_match = insert_url_pattern.search(line)
                if insert_match:
                    url = insert_match.group(1)
                    context = f"INSERT statement (line {line_number})"
                    found_urls.append((url, context))
                    
                    if verbose:
                        print(f"{Fore.GREEN}Found in INSERT: {url}{Style.RESET_ALL}")
                
                # Check for any other URLs in the line
                other_urls = config.URL_PATTERN.findall(line)
                for url in other_urls:
                    # Skip if already found by other patterns
                    if not any(found_url[0] == url for found_url in found_urls):
                        context = f"General pattern (line {line_number})"
                        found_urls.append((url, context))
                        
                        if verbose:
                            print(f"{Fore.GREEN}Found general URL: {url}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}Error reading SQL file: {e}{Style.RESET_ALL}")
    
    return found_urls

def main():
    args = parse_args()
    
    # Validate input file
    try:
        utils.validate_file_exists(args.input)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1
    
    if args.verbose:
        print(f"{Fore.CYAN}Analyzing MySQL dump: {args.input}{Style.RESET_ALL}")
        print("-" * 50)
    
    # Extract URLs from SQL dump
    urls = extract_and_process_data(args.input, args.verbose)
    
    # Filter URLs
    filtered_urls = utils.filter_urls(urls)
    
    # Print results
    if filtered_urls:
        print(f"\n{Fore.CYAN}Suspicious URL(s) found:{Style.RESET_ALL}")
        for url, context in filtered_urls:
            colored_output = highlight_and_append_text(url, context)
            print(colored_output)
    else:
        print(f"{Fore.GREEN}No suspicious URLs found{Style.RESET_ALL}")
    
    # Export to JSON if requested
    if args.json:
        md5, sha1, sha256 = utils.hash_file(args.input)
        data_to_export = {
            "urls": [{"url": url, "context": context} for url, context in filtered_urls],
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