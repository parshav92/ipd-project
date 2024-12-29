import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.arbitraryfrom_desc import *

def arbitraryfrom(contract):
    """
    Detects insecure usage of the transferFrom function in a smart contract.
    """
    r = re.compile(r'^.*transferFrom\(.*\).*')  # Match any line with transferFrom
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))  # Filter lines with transferFrom

    if not newlist:
        # Exit early if no transferFrom is found
        return

    stripped = [s.strip() for s in newlist]

    # Check for transferFrom using msg.sender
    r2 = re.compile(r'^.*transferFrom\(msg\.sender.*\).*')
    newlist2 = list(filter(r2.match, stripped))

    if not newlist2:
        # If no secure usage is found, flag as a vulnerability
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
