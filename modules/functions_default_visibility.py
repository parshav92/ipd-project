import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.funcdefvis import *

def function_default_visibility(contract):
    """
    Detects functions without explicit visibility modifiers in the smart contract.
    """
    # Match all function definitions
    r = re.compile(r'.*function .*\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)

    # Filter lines containing function definitions
    newlist = list(filter(r.match, parsed_contract_into_list))

    # List to hold line numbers of functions without visibility modifiers
    newlist_to_print = []

    # Iterate through each matched function definition
    for line in newlist:
        try:
            # Extract the function definition
            found = re.search(r'function .*(.*?).*', line).group(0)
            splited_words = found.split()

            # Check for missing or invalid visibility modifiers
            if len(splited_words) < 3 or splited_words[2] not in [
                'public', 'private', 'external', 'internal',
                'public{', 'private{', 'external{', 'internal{'
            ]:
                # Add the line number to the list
                line_number = 1 + parsed_contract_into_list.index(line)
                newlist_to_print.append(str(line_number))

        except AttributeError:
            # Skip lines that do not match the expected pattern
            pass

    # Format the list of line numbers for output
    newlist_printable = ', '.join(newlist_to_print)

    # Log vulnerability if any functions lack visibility modifiers
    if newlist_printable:
        printer_vuln(
            newlist_printable,
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )
        raise Exception("Vulnerability Detected")  # Raise exception for consistent logging
