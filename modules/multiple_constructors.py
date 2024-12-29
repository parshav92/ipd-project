import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln_whole_contract
from vulnerabilities_descriptions.multiplecons_desc import *

def multiple_constructors(contract):
    """
    Detects if the smart contract has multiple constructors (old-style or new-style).
    """
    parsed_contract_into_list = parse_contract(contract)

    # Exit early if the contract is empty
    if not parsed_contract_into_list:
        return  # Gracefully exit

    # Regex to detect old-style constructors (function with the same name as the contract)
    contract_name_pattern = re.compile(r'contract\s+(\w+)\s*{', re.IGNORECASE)
    contract_name_match = contract_name_pattern.search("\n".join(parsed_contract_into_list))

    if not contract_name_match:
        return  # No contract name found, gracefully exit

    contract_name = contract_name_match.group(1)
    old_constructor_pattern = re.compile(rf'function\s+{contract_name}\s*\(.*\)', re.IGNORECASE)

    # Regex to detect new-style constructors (constructor keyword)
    new_constructor_pattern = re.compile(r'\bconstructor\b\s*\(.*\)', re.IGNORECASE)

    # Search for old-style and new-style constructors
    old_style_constructors = list(filter(old_constructor_pattern.match, parsed_contract_into_list))
    new_style_constructors = list(filter(new_constructor_pattern.match, parsed_contract_into_list))

    # If more than one constructor is found (either old-style, new-style, or a mix)
    if len(old_style_constructors) + len(new_style_constructors) > 1:
        printer_vuln_whole_contract(
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )
    else:
        return  # Exit if no vulnerabilities are found
