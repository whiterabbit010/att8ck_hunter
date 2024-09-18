

# Sysmon Pattern Extractor and Analyzer with MITRE ATT&CK Integration

**Author**: wRabit /szymon
**Date**: _September 18, 2024_
**Version**: 1.0

---

## Overview

This project is an ongoing Python-based tool designed to extract patterns from Sysmon configuration files and match them with relevant MITRE ATT&CK techniques. The extracted patterns are dynamically matched using exact and fuzzy matching, providing insights into potential indicators of compromise based on MITRE's globally recognized framework (https://attack.mitre.org/).

The project is still in **development** and requires further improvements, but the core functionality is in place for users to:

- Extract patterns from Sysmon configuration files.
- Download MITRE ATT&CK attack-pattern data and merge them into a local dataset.
- Dynamically match Sysmon patterns with MITRE ATT&CK techniques using fuzzy matching.

## Features

- **Sysmon Pattern Extraction**: Parses Sysmon XML configuration files to extract relevant patterns like `CommandLine`, `Image`, etc.
- **MITRE ATT&CK Matching**: Matches extracted Sysmon patterns with MITRE ATT&CK techniques based on exact and fuzzy matching.
- **MITRE ATT&CK Dataset Management**: Downloads, updates, and merges MITRE ATT&CK data from the official GitHub repository into a single local JSON file.

## Current State

This project is still **in progress** and **requires improvements**, including:

1. Better handling of pattern edge cases.
2. Optimization of fuzzy matching for speed.
3. Additional pattern extraction capabilities from Sysmon logs.
4. Better error handling
5. enable logging

---

## Setup Instructions

### Prerequisites

- **Python 3.7+**
- Install the required libraries:
    
    `pip install requests lxml fuzzywuzzy[speedup]`
    

### Steps to Run the Project

1. **Clone the repository**:
    
```
    git clone https://github.com/whiterabbit010/att8ck_hunter.git
    cd att8ck_hunter
```

    
2. **Download MITRE ATT&CK Data**: To download the MITRE ATT&CK attack-pattern JSON files and merge them into a single dataset:
    
    `python mitre_attack_data_handler.py`
    
3. **Extract Patterns from Sysmon Config**: Once the MITRE ATT&CK data is available, you can extract patterns from Sysmon configuration files and match them with the techniques:
    
    `python sysmon_pattern_extractor.py`
    


---

## Next Steps and Improvements

- **Pattern Matching Enhancements**: Improve fuzzy matching for better accuracy and speed.
- **Sysmon Log Integration**: Extend the pattern extraction to work directly with Sysmon event logs.
- **Error Handling and Validation**: Implement robust error handling, especially for pattern extraction and MITRE ATT&CK matching.
- **Performance Optimizations**: Improve the performance of the pattern extraction and matching process.

Feel free to fork the repository, open issues, or submit pull requests to contribute to this project.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contributions

![May_be_the_wizz_with_you](thewizard.png)

**Author**: wRabit                                      
**Date**: _September 18, 2024_  
All contributions are welcome!

