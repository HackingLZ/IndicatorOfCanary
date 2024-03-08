#!/usr/bin/python3
import argparse
import base64
import re

from colorama import Fore, Style, init

init()

alert_list = {'internalcanarytokendomain.org', 'canarytokens.com'}

def parse_args():
    parser = argparse.ArgumentParser(description="Extract MySQL Dump b64/plaintext.")
    parser.add_argument("--input", "-i", required=True, help="Path to the input SQL dump file.")
    return parser.parse_args()

def url_in_list(url, lst):
    return any(domain in url for domain in lst)

def highlight_and_append_text(text, append_text):
    if url_in_list(text, alert_list):
        return f"{Fore.RED}{text}{Style.RESET_ALL} - {append_text}"
    else:
        return f"{text} - {append_text}"

def extract_and_print_data(sql_dump_path):
    set_base64_pattern = re.compile(r"SET\s+@\w+\s*=\s*'([^']+)'")
    set_master_host_pattern = re.compile(r"MASTER_HOST\s*=\s*'([^']+)'", re.IGNORECASE)
    
    with open(sql_dump_path, 'r', encoding='utf-8') as file:
        for line in file:
            base64_match = set_base64_pattern.search(line)
            master_host_match = set_master_host_pattern.search(line)
            
            if base64_match:
                base64_value = base64_match.group(1)
                try:
                    decoded_data = base64.b64decode(base64_value).decode('utf-8')
                    print(highlight_and_append_text(decoded_data, "BASE64"))
                except base64.binascii.Error:
                    continue
            
            if master_host_match:
                domain_name = master_host_match.group(1)
                print(highlight_and_append_text(domain_name, "CLEARTEXT"))

def main():
    args = parse_args()
    extract_and_print_data(args.input)

if __name__ == "__main__":
    main()
