#!/usr/bin/python3
# Based entirely on blogs below
# https://trufflesecurity.com/blog/canaries
# https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
# The intent here is to compare account IDs across an org to determine outliers(potential canaries)  

import argparse
import base64
import binascii
import csv

parser = argparse.ArgumentParser(description='Process AWS Key ID(s) to AWS Account ID(s)')
parser.add_argument('-k', '--keyid', type=str, help='Single AWS Key ID to process')
parser.add_argument('-f', '--file', type=str, help='File with AWS Key IDs, one per line')
parser.add_argument('--exportcsv', nargs='?', const='aws_keyid_accountid.csv', help='Export to CSV, optional filename')
args = parser.parse_args()

def acc_id_from_key(key_id):
    key = key_id[4:]
    decoded = base64.b32decode(key, casefold=True, map01='L')
    part = decoded[:6]
    number = int.from_bytes(part, 'big')
    mask = int.from_bytes(binascii.unhexlify('7fffffffff80'), 'big')
    return (number & mask) >> 7

def process_keys(keys):
    return [(k, acc_id_from_key(k)) for k in keys]

def export_csv(results, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['AWS Key ID', 'Amazon Account ID'])
        for k, acc_id in results:
            writer.writerow([k, f"{acc_id:012d}"])

keys = []

if args.keyid:
    keys.append(args.keyid)
elif args.file:
    with open(args.file) as f:
        keys = f.read().splitlines()

results = process_keys(keys)

if args.exportcsv:
    export_csv(results, args.exportcsv)
else:
    for k, acc_id in results:
        print(f"AWS Key ID: {k}, Amazon Account ID: {acc_id:012d}")
