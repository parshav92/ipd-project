import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln  # Ensure this is implemented and imported
from vulnerabilities_descriptions.arbitraryfrom_desc import *  # Vulnerability details should be defined here

def arbitraryfrom(contract):
    """
    Detects insecure usage of the transferFrom function in a smart contract.
    """
    # Regex to match transferFrom usage
    r = re.compile(r'^.*transferFrom\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)  # Parse contract into lines
    newlist = list(filter(r.match, parsed_contract_into_list))  # Filter lines with transferFrom

    # Strip whitespace for further analysis
    stripped = [s.strip() for s in newlist]

    # Regex to detect secure usage of transferFrom with msg.sender
    r2 = re.compile(r'^.*transferFrom\(msg\.sender.*\).*')
    newlist2 = list(filter(r2.match, stripped))  # Securely used lines

    newlist_to_print = []
    if not newlist2:  # If no secure usage is found
        for line in newlist:
            line_number = 1 + parsed_contract_into_list.index(line)  # Get 1-based line number
            newlist_to_print.append(str(line_number))

        # Print vulnerability details
        newlist_printable = ', '.join(newlist_to_print)
        printer_vuln(
            newlist_printable,
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )
