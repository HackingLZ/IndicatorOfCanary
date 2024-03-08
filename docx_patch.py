import argparse
import zipfile
import os
import re

def modify_all_files_in_zip(zip_path, search_pattern, replace_with):
    temp_dir = 'temp_unzip'
    os.makedirs(temp_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    modified_files = []

    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                contents = f.read()

            new_contents = re.sub(search_pattern, replace_with, contents)
            if new_contents != contents:
                with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(new_contents)
                modified_files.append(os.path.relpath(file_path, temp_dir))

    modified_zip_path = zip_path.replace('.docx', '_patched.docx')
    with zipfile.ZipFile(modified_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, temp_dir))


    for root, dirs, files in os.walk(temp_dir, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(temp_dir)

    return modified_zip_path, modified_files

def main():
    parser = argparse.ArgumentParser(description='Replace canary URL in .docx')
    parser.add_argument('-i', '--input', required=True, help='Input .docx file path')
    
    args = parser.parse_args()
    zip_path = args.input
    search_pattern = re.escape('http://canarytokens.com/feedback/about/1234/submit.aspx')
    replace_with = 'http://hacktheplanet/tracker/1234.php'

    modified_zip_path, modified_files = modify_all_files_in_zip(zip_path, search_pattern, replace_with)
    print(f"Modified document saved to {modified_zip_path}")
    if modified_files:
        print("Modified files within the .docx:")
        for file in modified_files:
            print(f"- {file}")
    else:
        print("No files were modified.")

if __name__ == "__main__":
    main()
