import click
import re
import os
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.storedcreds_desc import *

def stored_credentials(contract):
    """
    Detects possible storage of credentials in the smart contract.
    """
    # Check if the passwords file exists
    password_file = "1kpasswords.txt"
    if not os.path.exists(password_file):
        print(f"Password file '{password_file}' not found. Skipping stored credentials check.")
        return None  # Explicitly return None

    parsed_contract_into_list = parse_contract(contract)

    # Load and prepare password list
    with open(password_file, 'r', encoding="utf-8") as f:
        passwords = [line.strip() for line in f.readlines()]

    # Ignore lines with `import` statements or comments
    filtered_lines = [
        line for line in parsed_contract_into_list
        if not line.strip().startswith("import") and not line.strip().startswith("//")
    ]

    # Search for stored credentials
    newlist = []
    for password in passwords:
        formula = r'^(.*?(\b' + re.escape(password) + r'\b)[^$]*)$'
        r = re.compile(formula, re.IGNORECASE)
        newlist += list(filter(r.match, filtered_lines))

    if newlist:
        newlist_to_print = [
            str(1 + parsed_contract_into_list.index(line)) for line in newlist
        ]
        newlist_noduplics = list(dict.fromkeys(newlist_to_print))  # Remove duplicates
        newlist_printable = ', '.join(newlist_noduplics)

        # Use printer
        printer_vuln(
            newlist_printable,
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )

        return f"Stored Credentials vulnerability found at line(s): {newlist_printable}"
    
    return None  # Explicitly return None if no vulnerabilities found
