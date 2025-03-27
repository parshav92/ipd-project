import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln  # Updated import
from vulnerabilities_descriptions.insecrandoms_desc import *  # Ensure this is correct

def randomsource(contract):
    r = re.compile(r'^.*blockhash.*|^.*block\.timestamp.*|^.*block\.difficulty.*')
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.search, parsed_contract_into_list))

    newlist_to_print = []
    
    if newlist:
        for item in newlist:
            line_number = 1 + parsed_contract_into_list.index(item)
            newlist_to_print.append(str(line_number))

        newlist_printable = ', '.join(newlist_to_print)

        printer_vuln(
            newlist_printable,
            "Insecure Random Source",
            "Using block data for randomness is insecure.",
            "Use Chainlink VRF or another cryptographically secure source of randomness.",
            ["https://docs.chain.link/docs/chainlink-vrf/"]
        )
        
        return f"Insecure Random Source vulnerability found at line(s): {newlist_printable}"
    
    return None  # Explicitly return None if no vulnerabilities found
