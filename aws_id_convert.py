#!/usr/bin/python3
"""
Convert AWS Access Key IDs to Account IDs for canary detection
Based on research from:
- https://trufflesecurity.com/blog/canaries
- https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489

The intent is to compare account IDs across an organization to identify outliers 
(potential canaries) by finding uncommon account IDs that may require additional scrutiny.
"""

import argparse
import base64
import binascii
import csv
import os
from colorama import Fore, Style, init
import canary_config as config
import canary_utils as utils

init()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Convert AWS Access Key ID(s) to Account ID(s)',
        epilog='Example: %(prog)s -k AKIAIOSFODNN7EXAMPLE or %(prog)s -f keys.txt'
    )
    parser.add_argument('-k', '--keyid', type=str, 
                      help='Single AWS Access Key ID to process')
    parser.add_argument('-f', '--file', type=str, 
                      help='File with AWS Access Key IDs, one per line')
    parser.add_argument('--exportcsv', nargs='?', const='aws_keyid_accountid.csv', 
                      help='Export results to CSV file (optional custom filename)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose output with validation')
    return parser.parse_args()

def validate_aws_key_format(key_id):
    """
    Validate AWS Access Key ID format
    
    Args:
        key_id: AWS Access Key ID to validate
        
    Returns:
        True if valid format, False otherwise
    """
    if not key_id or len(key_id) != 20:
        return False
    
    if not key_id.startswith('AKIA'):
        return False
    
    # Check if remaining characters are valid base32
    key_part = key_id[4:]
    try:
        base64.b32decode(key_part, casefold=True, map01='L')
        return True
    except:
        return False

def acc_id_from_key(key_id):
    """
    Extract AWS Account ID from Access Key ID
    
    Args:
        key_id: AWS Access Key ID
        
    Returns:
        AWS Account ID as integer
        
    Raises:
        ValueError: If key format is invalid
    """
    if not validate_aws_key_format(key_id):
        raise ValueError(f"Invalid AWS Access Key ID format: {key_id}")
    
    try:
        key = key_id[4:]  # Remove 'AKIA' prefix
        decoded = base64.b32decode(key, casefold=True, map01='L')
        part = decoded[:6]  # First 6 bytes
        number = int.from_bytes(part, 'big')
        mask = int.from_bytes(binascii.unhexlify('7fffffffff80'), 'big')
        account_id = (number & mask) >> 7
        return account_id
    except Exception as e:
        raise ValueError(f"Failed to decode key {key_id}: {e}")

def process_keys(keys, verbose=False):
    """
    Process list of AWS Access Key IDs
    
    Args:
        keys: List of AWS Access Key IDs
        verbose: Print verbose output
        
    Returns:
        List of (key_id, account_id, is_suspicious) tuples
    """
    results = []
    
    for key in keys:
        key = key.strip()
        if not key:
            continue
            
        try:
            account_id = acc_id_from_key(key)
            account_id_str = f"{account_id:012d}"
            
            # Check if this is a known canary account
            is_suspicious = account_id_str in config.KNOWN_CANARY_ACCOUNTS
            
            results.append((key, account_id, is_suspicious))
            
            if verbose:
                if is_suspicious:
                    print(f"{Fore.RED}⚠ Suspicious key: {key} -> {account_id_str} (Known canary account){Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}✓ Valid key: {key} -> {account_id_str}{Style.RESET_ALL}")
                    
        except ValueError as e:
            if verbose:
                print(f"{Fore.YELLOW}✗ Invalid key: {key} ({e}){Style.RESET_ALL}")
            results.append((key, None, False))
    
    return results

def export_csv(results, filename, verbose=False):
    """
    Export results to CSV file
    
    Args:
        results: List of (key_id, account_id, is_suspicious) tuples
        filename: Output CSV filename
        verbose: Print verbose output
    """
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['AWS Access Key ID', 'AWS Account ID', 'Status', 'Notes'])
            
            for key_id, account_id, is_suspicious in results:
                if account_id is not None:
                    account_id_str = f"{account_id:012d}"
                    status = "SUSPICIOUS" if is_suspicious else "NORMAL"
                    notes = "Known canary account" if is_suspicious else ""
                else:
                    account_id_str = "INVALID"
                    status = "ERROR"
                    notes = "Invalid key format"
                
                writer.writerow([key_id, account_id_str, status, notes])
        
        if verbose:
            print(f"{Fore.GREEN}✓ Results exported to: {filename}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}Error writing CSV: {e}{Style.RESET_ALL}")

def analyze_account_ids(results, verbose=False):
    """
    Analyze account IDs for patterns and outliers
    
    Args:
        results: List of (key_id, account_id, is_suspicious) tuples
        verbose: Print verbose output
        
    Returns:
        Dictionary with analysis results
    """
    valid_results = [(k, a, s) for k, a, s in results if a is not None]
    
    if not valid_results:
        return {}
    
    account_ids = [account_id for _, account_id, _ in valid_results]
    unique_accounts = set(account_ids)
    
    # Count occurrences
    account_counts = {}
    for account_id in account_ids:
        account_counts[account_id] = account_counts.get(account_id, 0) + 1
    
    # Find outliers (accounts with only one key)
    outliers = [acc for acc, count in account_counts.items() if count == 1]
    
    analysis = {
        'total_keys': len(valid_results),
        'unique_accounts': len(unique_accounts),
        'outlier_accounts': len(outliers),
        'suspicious_accounts': sum(1 for _, _, is_susp in valid_results if is_susp),
        'account_distribution': account_counts
    }
    
    if verbose:
        print(f"\n{Fore.CYAN}Analysis Summary:{Style.RESET_ALL}")
        print(f"  Total valid keys: {analysis['total_keys']}")
        print(f"  Unique accounts: {analysis['unique_accounts']}")
        print(f"  Outlier accounts (single key): {analysis['outlier_accounts']}")
        print(f"  Known suspicious accounts: {analysis['suspicious_accounts']}")
        
        if outliers:
            print(f"\n{Fore.YELLOW}Outlier accounts (require investigation):{Style.RESET_ALL}")
            for account_id in outliers:
                account_str = f"{account_id:012d}"
                is_known = account_str in config.KNOWN_CANARY_ACCOUNTS
                color = Fore.RED if is_known else Fore.YELLOW
                status = " (KNOWN CANARY)" if is_known else ""
                print(f"  {color}{account_str}{status}{Style.RESET_ALL}")
    
    return analysis

def main():
    args = parse_args()
    
    # Collect keys from arguments
    keys = []
    
    if args.keyid:
        keys.append(args.keyid)
    elif args.file:
        try:
            utils.validate_file_exists(args.file)
            with open(args.file, 'r') as f:
                keys = f.read().splitlines()
        except (FileNotFoundError, ValueError, PermissionError) as e:
            print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")
            return 1
    else:
        print(f"{Fore.RED}Error: Must specify either -k/--keyid or -f/--file{Style.RESET_ALL}")
        return 1
    
    if not keys:
        print(f"{Fore.RED}Error: No keys to process{Style.RESET_ALL}")
        return 1
    
    if args.verbose:
        print(f"{Fore.CYAN}Processing {len(keys)} AWS Access Key ID(s)...{Style.RESET_ALL}")
        print("-" * 50)
    
    # Process the keys
    results = process_keys(keys, args.verbose)
    
    # Export to CSV if requested
    if args.exportcsv:
        export_csv(results, args.exportcsv, args.verbose)
    else:
        # Print results to console
        print(f"\n{Fore.CYAN}Results:{Style.RESET_ALL}")
        for key_id, account_id, is_suspicious in results:
            if account_id is not None:
                account_str = f"{account_id:012d}"
                if is_suspicious:
                    print(f"{Fore.RED}AWS Key ID: {key_id}, Account ID: {account_str} (SUSPICIOUS){Style.RESET_ALL}")
                else:
                    print(f"AWS Key ID: {key_id}, Account ID: {account_str}")
            else:
                print(f"{Fore.YELLOW}AWS Key ID: {key_id}, Account ID: INVALID{Style.RESET_ALL}")
    
    # Perform analysis
    analysis = analyze_account_ids(results, args.verbose)
    
    # Return non-zero if suspicious accounts found
    if analysis.get('suspicious_accounts', 0) > 0:
        return 2  # Different exit code for suspicious findings
    
    return 0

if __name__ == "__main__":
    exit(main())