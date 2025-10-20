#!/usr/bin/python3
"""
Patch/replace canary URLs in DOCX files
Allows replacing known canary URLs with custom URLs
"""

import argparse
import zipfile
import os
import re
import tempfile
import shutil
from colorama import Fore, Style, init
import canary_config as config
import canary_utils as utils

init()

def modify_all_files_in_zip(zip_path, search_pattern, replace_with, verbose=False):
    """
    Modify all matching URLs in a DOCX file
    
    Args:
        zip_path: Path to input DOCX file
        search_pattern: Pattern to search for
        replace_with: Replacement string
        verbose: Print detailed progress
        
    Returns:
        Tuple of (modified_zip_path, modified_files)
    """
    # Use proper temp directory
    temp_dir = tempfile.mkdtemp(prefix='docx_patch_')
    
    try:
        # Extract the DOCX
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        modified_files = []
        
        # Process all files
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, temp_dir)
                
                # Skip binary files
                if file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        contents = f.read()
                    
                    # Perform replacement
                    new_contents = re.sub(search_pattern, replace_with, contents)
                    
                    if new_contents != contents:
                        with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(new_contents)
                        modified_files.append(relative_path)
                        
                        if verbose:
                            print(f"{Fore.GREEN}✓{Style.RESET_ALL} Modified: {relative_path}")
                except Exception as e:
                    if verbose:
                        print(f"{Fore.YELLOW}⚠{Style.RESET_ALL} Skipped {relative_path}: {e}")
        
        # Create output filename
        base_name = os.path.splitext(os.path.basename(zip_path))[0]
        modified_zip_path = f"{base_name}_patched.docx"
        
        # Create new DOCX with modified content
        with zipfile.ZipFile(modified_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arc_path = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arc_path)
        
        return modified_zip_path, modified_files
        
    finally:
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Replace canary URLs in .docx files',
        epilog='Example: %(prog)s -i document.docx -s "canarytokens.com" -r "safe.example.com"'
    )
    parser.add_argument('-i', '--input', required=True, 
                      help='Input .docx file path')
    parser.add_argument('-s', '--search', 
                      help='URL/pattern to search for (if not specified, replaces all known canary domains)')
    parser.add_argument('-r', '--replace', '--host', required=True,
                      help='Replacement URL/host')
    parser.add_argument('-o', '--output',
                      help='Output file path (default: input_patched.docx)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose output')
    parser.add_argument('--regex', action='store_true',
                      help='Treat search pattern as regex')
    
    return parser.parse_args()

def build_search_pattern(search_str, use_regex):
    """
    Build search pattern from string
    
    Args:
        search_str: Search string or None for all canary domains
        use_regex: Whether to treat as regex
        
    Returns:
        Compiled regex pattern
    """
    if search_str:
        if use_regex:
            return search_str
        else:
            # Escape special regex characters
            return re.escape(search_str)
    else:
        # Build pattern for all known canary domains
        domains = '|'.join(re.escape(domain) for domain in config.ALERT_DOMAINS)
        return f'https?://(?:[\\w.-]+\\.)?(?:{domains})(?:/[\\w.-]*)*'

def main():
    args = parse_args()
    
    # Validate input file
    try:
        utils.validate_file_exists(args.input)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1
    
    # Build search pattern
    search_pattern = build_search_pattern(args.search, args.regex)
    
    if args.verbose:
        print(f"Input file: {args.input}")
        if args.search:
            print(f"Search pattern: {args.search}")
        else:
            print(f"Replacing all known canary domains")
        print(f"Replacement: {args.replace}")
        print("-" * 50)
    
    try:
        # Perform the patching
        modified_zip_path, modified_files = modify_all_files_in_zip(
            args.input, 
            search_pattern, 
            args.replace,
            args.verbose
        )
        
        # Rename to custom output if specified
        if args.output:
            shutil.move(modified_zip_path, args.output)
            modified_zip_path = args.output
        
        print(f"\n{Fore.GREEN}✓{Style.RESET_ALL} Modified document saved to: {modified_zip_path}")
        
        if modified_files:
            print(f"\n{Fore.CYAN}Modified {len(modified_files)} file(s) within the .docx:{Style.RESET_ALL}")
            if not args.verbose:  # Don't repeat if already shown
                for file in modified_files[:10]:  # Show first 10
                    print(f"  - {file}")
                if len(modified_files) > 10:
                    print(f"  ... and {len(modified_files) - 10} more")
        else:
            print(f"{Fore.YELLOW}⚠{Style.RESET_ALL} No files were modified (pattern not found)")
        
        return 0
        
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    exit(main())