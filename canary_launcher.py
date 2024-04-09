import os
import subprocess
import json
import tempfile
import time

# Mapping file extensions to corresponding Python scripts
file_mapping = {
    '.docx': 'docx_canary.py',
    '.sql': 'mysql_canary.py',
    '.pptx': 'pptx_canary.py',
    '.xlsx': 'xlsx_canary.py',
}

def process_file(file_path, temp_json_path, generate_json):
    _, extension = os.path.splitext(file_path)

    if extension in file_mapping:
        script_name = file_mapping[extension]
        command = f"python {script_name} --input \"{file_path}\""
        # Add JSON output option if JSON generation is requested
        if generate_json:
            temp_output = f"{temp_json_path}/{int(time.time() * 1000)}.json"
            command += f" --json \"{temp_output}\""
        print(f"Executing: {command}")
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing {script_name} on {file_path}: {e}")

def explore_directory(directory, temp_json_path, generate_json):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            process_file(file_path, temp_json_path, generate_json)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Explore a directory and execute scripts based on file extensions.")
    parser.add_argument('--directory', '-d', type=str, required=True, help="Path to the directory to explore.")
    parser.add_argument('--json', '-j', type=str, help="Output path for the combined JSON file.")
    args = parser.parse_args()

    generate_json = bool(args.json)

    if generate_json:
        with tempfile.TemporaryDirectory() as tmp_dir:
            explore_directory(args.directory, tmp_dir, generate_json)

            # Combine all the JSON results into one file
            combined_results = []
            for root, dirs, files in os.walk(tmp_dir):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            try:
                                json_data = json.load(f)
                                combined_results.extend(json_data if isinstance(json_data, list) else [json_data])
                            except json.JSONDecodeError as e:
                                print(f"Error decoding JSON from {file_path}: {e}")

            with open(args.json, 'w') as f:
                json.dump(combined_results, f, indent=4)

            print(f"All results have been combined into {args.json}")
    else:
        # Just execute the scripts without generating JSON output
        explore_directory(args.directory, None, generate_json)
