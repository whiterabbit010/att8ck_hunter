# sysmon_pattern_extractor.py
import os
from lxml import etree
from mitre_attack_lookup import load_mitre_attack_data, lookup_mitre_attack

def extract_patterns_from_sysmon_config_v7(config_files, output_xml_file, mitre_attack_data):
    """
    Extracts patterns from Sysmon configuration files and appends MITRE ATT&CK references dynamically with fuzzy matching.
    Args:
        config_files (list): List of paths to Sysmon XML configuration files.
        output_xml_file (str): Path to save the output XML with extracted patterns.
        mitre_attack_data (list): List of MITRE ATT&CK techniques.
    Returns:
        dict: A dictionary where keys are event attributes (CommandLine, Image, etc.) and values are lists of patterns and conditions.
    """
    all_patterns = {}

    # Create XML root for output
    root = etree.Element("Patterns")

    for config_file in config_files:
        try:
            print(f"Processing file: {config_file}")
            tree = etree.parse(config_file)
            root_tree = tree.getroot()

            # Find all RuleGroup sections in the configuration
            for rule_group in root_tree.xpath(".//RuleGroup"):
                for element in rule_group.xpath(".//ProcessCreate | .//NetworkConnect | .//FileCreate | .//RegistryEvent"):
                    event_type = element.tag

                    # Search for CommandLine, Image, ParentCommandLine, etc.
                    for sub_element in element.xpath(".//CommandLine | .//Image | .//ParentCommandLine | .//ParentImage | .//IntegrityLevel"):
                        pattern_text = sub_element.text.strip() if sub_element.text else ""
                        condition = sub_element.attrib.get('condition', '').strip()

                        if pattern_text and condition:
                            print(f"Extracting pattern: {pattern_text} with condition: {condition}")

                            # Look up MITRE ATT&CK technique using fuzzy matching
                            technique_id, technique_url = lookup_mitre_attack(pattern_text, mitre_attack_data)

                            # Store the pattern and condition in the dictionary
                            if event_type not in all_patterns:
                                all_patterns[event_type] = []
                            all_patterns[event_type].append({
                                "pattern": pattern_text,
                                "condition": condition,
                                "technique_id": technique_id,
                                "technique_url": technique_url
                            })

                            # Create XML structure for output
                            pattern_element = etree.SubElement(root, "Pattern")
                            pattern_element.set("Type", event_type)
                            pattern_element.set("Condition", condition)
                            pattern_element.text = pattern_text

                            # Add a description or reference as a comment
                            if technique_id and technique_url:
                                comment = etree.Comment(f"MITRE ATT&CK Technique: {technique_id}, {technique_url}")
                            else:
                                comment = etree.Comment("No MITRE ATT&CK reference found.")
                            root.append(comment)

        except Exception as e:
            print(f"Error reading Sysmon config file {config_file}: {e}")

    # Write to output XML file
    tree = etree.ElementTree(root)
    tree.write(output_xml_file, pretty_print=True, encoding='utf-8', xml_declaration=True)

    return all_patterns

# Define the paths to the Sysmon configuration files
sysmon_config_paths_v7 = [
    r'C.\Users\pathtoyour\file\sysmonconfig-export_ion-storm.xml',
    r'\path\to\your\config\file\sysmonconfig-export_swift.xml'
]

# Define the output XML file
# check if folder PatternFiles in the working directory exists, if not create it

if not os.path.exists('PatternFiles'):
    os.makedirs('PatternFiles')
output_xml_file = os.path.join(os.getcwd(), 'PatternFiles', 'extracted_patterns_v7.xml')

# Load MITRE ATT&CK dataset
mitre_attack_data = load_mitre_attack_data('mitre_attack_data.json')

# Run the pattern extraction function with MITRE ATT&CK lookup
extracted_patterns_v7 = extract_patterns_from_sysmon_config_v7(sysmon_config_paths_v7, output_xml_file, mitre_attack_data)

# Print the extracted patterns for review
print(extracted_patterns_v7)
