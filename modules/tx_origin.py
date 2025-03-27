import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.tx_origin_desc import *

def tx_origin(contract):
    """
    Detects the use of tx.origin for authentication, which is vulnerable to phishing attacks.
    """
    r = re.compile(r'^.*tx.origin == owner.*')  # Regex to find tx.origin usage
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))

    if newlist:
        newlist_to_print = [
            str(1 + parsed_contract_into_list.index(line)) for line in newlist
        ]
        
        # Remove duplicate line numbers
        newlist_noduplics = list(dict.fromkeys(newlist_to_print))  
        newlist_printable = ', '.join(newlist_noduplics)

        # Use printer
        printer_vuln(
            newlist_printable,
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )

        return f"Tx.origin vulnerability found at line(s): {newlist_printable}"
    
    return None  # Explicitly return None if no vulnerabilities found
