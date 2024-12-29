import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.arbitraryfrom_desc import *

def arbitraryfrom(contract):
    """
    Detects insecure usage of the transferFrom function in a smart contract.
    """
    # Match any line with transferFrom
    r = re.compile(r'^.*transferFrom\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)

    # Filter lines with transferFrom
    newlist = list(filter(r.match, parsed_contract_into_list))

    if not newlist:
        # Exit early if no transferFrom is found
        return  # Graceful exit with no vulnerabilities detected

    # Strip whitespace for further processing
    stripped = [s.strip() for s in newlist]

    # Check for transferFrom using msg.sender
    r2 = re.compile(r'^.*transferFrom\(msg\.sender.*\).*')
    newlist2 = list(filter(r2.match, stripped))

    if not newlist2:
        newlist_to_print = [
        str(1 + parsed_contract_into_list.index(line)) for line in newlist
        ]
        printer_vuln(
            ', '.join(newlist_to_print),
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )
        raise Exception("Vulnerability Detected")  # Raise exception for summary

    else:
        # Explicitly exit if all instances of transferFrom are securely implemented
        return  # No vulnerability detected
