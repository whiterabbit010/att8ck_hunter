import os
import requests
import json

# Define the GitHub API URL for the attack-pattern directory
GITHUB_API_URL = "https://api.github.com/repos/mitre/cti/contents/enterprise-attack/attack-pattern"

# GitHub Raw URL to download files
RAW_GITHUB_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern"

# Metadata file to store information about downloaded files
METADATA_FILE = "downloaded_files.json"

def load_downloaded_files(metadata_file):
    """
    Loads the list of downloaded files from the local metadata file.
    Args:
        metadata_file (str): Path to the metadata file.
    Returns:
        dict: A dictionary of file metadata (file names and SHAs).
    """
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            return json.load(f)
    return {}

def save_downloaded_files(metadata_file, downloaded_files):
    """
    Saves the metadata of downloaded files to a local file.
    Args:
        metadata_file (str): Path to the metadata file.
        downloaded_files (dict): Dictionary of file metadata (file names and SHAs).
    """
    with open(metadata_file, 'w') as f:
        json.dump(downloaded_files, f, indent=4)

def download_attack_patterns(destination_folder):
    """
    Downloads only new or updated JSON files from the MITRE ATT&CK attack-pattern directory on GitHub.
    Args:
        destination_folder (str): The directory where the files will be downloaded.
    """
    # Load metadata of already downloaded files
    downloaded_files = load_downloaded_files(METADATA_FILE)

    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    # Get the list of files in the attack-pattern directory from GitHub
    response = requests.get(GITHUB_API_URL)
    if response.status_code != 200:
        print(f"Failed to retrieve file list from GitHub API. Status Code: {response.status_code}")
        return

    files = response.json()
    updated_files = {}

    for file_info in files:
        if file_info['name'].endswith('.json'):
            file_url = f"{RAW_GITHUB_URL}/{file_info['name']}"
            file_path = os.path.join(destination_folder, file_info['name'])
            file_sha = file_info['sha']

            # Check if the file has already been downloaded
            if file_info['name'] in downloaded_files and downloaded_files[file_info['name']] == file_sha:
                print(f"{file_info['name']} is already up-to-date. Skipping download.")
                continue

            # Download new or updated files
            print(f"Downloading {file_info['name']}...")
            file_response = requests.get(file_url)
            if file_response.status_code == 200:
                with open(file_path, 'wb') as file:
                    file.write(file_response.content)
                
                # Save the new file's metadata
                updated_files[file_info['name']] = file_sha
            else:
                print(f"Failed to download {file_info['name']}. Status Code: {file_response.status_code}")

    # Update the metadata with the new downloaded files
    downloaded_files.update(updated_files)
    save_downloaded_files(METADATA_FILE, downloaded_files)

    if updated_files:
        print("New or updated attack-pattern files downloaded.")
    else:
        print("No new attack-pattern files found.")

def merge_attack_pattern_files(source_folder, output_file):
    """
    Merges all JSON files from a directory into a single JSON file.
    Args:
        source_folder (str): The directory containing the JSON files to merge.
        output_file (str): The output JSON file path.
    """
    all_patterns = []

    # Loop through all files in the source folder
    for file_name in os.listdir(source_folder):
        if file_name.endswith('.json'):
            file_path = os.path.join(source_folder, file_name)

            # Read the JSON file and add its contents to the list
            with open(file_path, 'r') as f:
                data = json.load(f)
                all_patterns.append(data)

    # Write the merged data to the output file
    with open(output_file, 'w') as out_file:
        json.dump(all_patterns, out_file, indent=4)

    print(f"Merged data saved to {output_file}")

# Example usage in the same file
if __name__ == "__main__":
    # Step 1: Download only new or updated attack-pattern files
    download_attack_patterns("attack-patterns")

    # Step 2: Merge the files into one JSON
    merge_attack_pattern_files("attack-patterns", "mitre_attack_data.json")
