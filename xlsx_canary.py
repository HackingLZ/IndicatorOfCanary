#!/usr/bin/python3
import json
import re
import zipfile
import argparse
import hashlib
from urllib.parse import urlparse
from openpyxl import load_workbook
from datetime import datetime
from colorama import Fore, Style, init

init()

ignore_list = {'purl.org', 'microsoft.com', 'openxmlformats.org', 'w3.org'}
alert_list = {'internalcanarytokendomain.org', 'canarytokens.com', 'allsafelink.com', 'whiteclouddrive.com'}
badauthor_list = {'openpyxl'}
url_pattern = re.compile(r"https?://[\w.-]+(?::\d+)?(?:[/\w .-]*)?", re.IGNORECASE)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", required=True, help="Input file (.xlsx)")
    parser.add_argument("--json", "-j", help="Output JSON file path")
    return parser.parse_args()

def url_in_list(url, lst):
    return any(urlparse(url).hostname.endswith(domain) for domain in lst)

def extract_urls_from_file(file_content, filename):
    urls = url_pattern.findall(file_content.decode('utf-8', errors='ignore'))
    return [(url, filename) for url in urls]

def filter_urls(urls, ignore_list):
    return [url for url in urls if not url_in_list(url[0], ignore_list)]

def print_colored_urls(urls, alert_list):
    for url, location in urls:
        color = Fore.YELLOW
        if url_in_list(url, alert_list):
            color = Fore.RED
        print(f"{color}{url} - {location}{Style.RESET_ALL}")

def hash_file(file_path):
    with open(file_path, "rb") as f:
        file_content = f.read()
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    return md5, sha1

def write_to_json(output_path, file_name, data):
    with open(output_path, "w") as f:
        json.dump({file_name: data}, f, indent=4)

def extract_xlsx_meta(xlsx_path):
    wb = load_workbook(xlsx_path, data_only=True)
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

    return meta_data


def main():
    args = parse_args()

    meta_data = extract_xlsx_meta(args.input)
    if meta_data:
        print("Metadata:")
        for prop, value in meta_data.items():
            if prop == "creator" and value.lower() in badauthor_list:
                print(f"{Fore.RED}{prop}: {value}{Style.RESET_ALL}")
            else:
                print(f"{prop}: {value}")
    print("\nURL(s):")

    with zipfile.ZipFile(args.input) as zipped_xlsx:
        urls = [extract_urls_from_file(zipped_xlsx.read(file.filename), file.filename)
                for file in zipped_xlsx.filelist if not file.is_dir() and not file.filename.startswith('xl/media/')]
        urls = sum(urls, [])
        urls = filter_urls(urls, ignore_list)
    print_colored_urls(urls, alert_list)

    if args.json:
        md5, sha1 = hash_file(args.input)
        data_to_export = {
            "meta": meta_data,
            "urls": [{"url": url, "location": location} for url, location in urls],
            "md5": md5,
            "sha1": sha1
        }
        write_to_json(args.json, args.input.split('/')[-1], data_to_export)
        print(f"\nResults have been written to {args.json}")

if __name__ == "__main__":
    main()
