# mitre_attack_lookup.py
import json
import re
from fuzzywuzzy import fuzz

def load_mitre_attack_data(file_path='mitre_attack_data.json'):
    """
    Loads MITRE ATT&CK data from a JSON file.
    Args:
        file_path (str): Path to the MITRE ATT&CK JSON dataset.
    Returns:
        list: A list of MITRE ATT&CK techniques.
    """
    with open(file_path, 'r') as f:
        return json.load(f)

def normalize_text(text):
    """
    Normalizes the input text by lowercasing and removing extra spaces.
    Args:
        text (str): The input string to normalize.
    Returns:
        str: Normalized text.
    """
    return re.sub(r'\s+', ' ', text.strip().lower())

def fuzzy_match(pattern, description, threshold=80):
    """
    Performs fuzzy matching between two strings using a similarity threshold.
    Args:
        pattern (str): The pattern to match.
        description (str): The description to match against.
        threshold (int): The similarity threshold (0-100). Default is 80.
    Returns:
        bool: True if the fuzzy match score is above the threshold, False otherwise.
    """
    return fuzz.token_set_ratio(normalize_text(pattern), normalize_text(description)) >= threshold

def lookup_mitre_attack(pattern, mitre_attack_data, threshold=80):
    """
    Searches the MITRE ATT&CK data for a matching pattern using fuzzy matching and returns the corresponding technique ID and URL.
    Args:
        pattern (str): The pattern to look up in the MITRE ATT&CK data.
        mitre_attack_data (list): List of MITRE ATT&CK techniques (JSON format).
        threshold (int): The similarity threshold for fuzzy matching. Default is 80.
    Returns:
        tuple: The technique ID and URL if a match is found, otherwise None.
    """
    normalized_pattern = normalize_text(pattern)
    for technique in mitre_attack_data:
        technique_description = technique.get('description', '')
        technique_name = technique.get('name', '')

        # Perform fuzzy matching on both description and name
        if fuzzy_match(normalized_pattern, technique_description, threshold) or \
           fuzzy_match(normalized_pattern, technique_name, threshold):
            return technique['technique_id'], technique['url']
    
    return None, None
