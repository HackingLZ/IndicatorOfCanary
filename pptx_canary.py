#!/usr/bin/python3
import json
import re
import zipfile
import argparse
import hashlib
from urllib.parse import urlparse
from pptx import Presentation
from colorama import Fore, Style, init
from datetime import datetime

init()

ignore_list = {'purl.org', 'microsoft.com', 'openxmlformats.org', 'w3.org', 'publicdomainpictures.net', 'dublincore.org'}
alert_list = {'internalcanarytokendomain.org', 'canarytokens.com', 'allsafelink.com', 'whiteclouddrive.com'}
url_pattern = re.compile(r"https?://[\w.-]+(?::\d+)?(?:[/\w .-]*)?", re.IGNORECASE)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", required=True, help="Input file")
    parser.add_argument("--json", "-j", help="Output JSON file path")
    return parser.parse_args()

def url_in_list(url, lst):
    return any(urlparse(url).hostname.endswith(domain) for domain in lst)

def extract_urls_from_file(file_content, filename):
    urls = url_pattern.findall(file_content.decode('utf-8'))
    return [(url, filename) for url in urls]

def filter_urls(urls, ignore_list):
    return [url for url in urls if not url_in_list(url[0], ignore_list)]

def print_colored_urls(urls, alert_list):
    for url, filename in urls:
        if url_in_list(url, alert_list):
            color = Fore.RED
        else:
            color = Fore.YELLOW
        print(f"{color}{url} - {filename}{Style.RESET_ALL}")

def extract_pptx_meta(pptx_path):
    prs = Presentation(pptx_path)
    properties = prs.core_properties
    meta_data = {prop: getattr(properties, prop) for prop in dir(properties) if not prop.startswith('_') and not callable(getattr(properties, prop))}
    meta_data = {prop: value.isoformat() if isinstance(value, datetime) else value for prop, value in meta_data.items() if value}
    return meta_data

def hash_file(file_path):
    with open(file_path, "rb") as f:
        file_content = f.read()
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    return md5, sha1

def write_to_json(output_path, file_name, data):
    with open(output_path, "w") as f:
        json.dump({file_name: data}, f, indent=4)

def main():
    args = parse_args()

    meta_data = extract_pptx_meta(args.input)
    print("Metadata:")
    for prop, value in meta_data.items():
        print(f"{prop}: {value}")
    print("\nURL(s):")

    with zipfile.ZipFile(args.input) as doc:
        urls = [extract_urls_from_file(doc.read(file.filename), file.filename) for file in doc.filelist if file.filename.endswith('.xml') or file.filename.endswith('.rels')]
        urls = sum(urls, [])
        urls = filter_urls(urls, ignore_list)
        print_colored_urls(urls, alert_list)

    if args.json:
        md5, sha1 = hash_file(args.input)
        data_to_export = {
            "meta": meta_data,
            "urls": [{"url": url, "location": filename} for url, filename in urls],
            "md5": md5,
            "sha1": sha1
        }
        write_to_json(args.json, args.input.split('/')[-1], data_to_export)
        print(f"\nResults have been written to {args.json}")

if __name__ == "__main__":
    main()
