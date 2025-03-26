import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.arbitraryfrom_desc import *

def arbitraryfrom(contract):
    """
    Detects insecure usage of the transferFrom function in a smart contract.
    """
    r = re.compile(r'transferFrom\(.*\)')
    parsed_contract_into_list = parse_contract(contract)
    
    newlist = [line for line in parsed_contract_into_list if r.search(line)]
    
    if not newlist:
        return None  # No vulnerability detected
    
    r2 = re.compile(r'transferFrom\(msg\.sender.*\)')
    insecure_lines = [line for line in newlist if not r2.search(line)]
    
    if insecure_lines:
        newlist_to_print = [str(parsed_contract_into_list.index(line) + 1) for line in insecure_lines]
        newlist_printable = ', '.join(newlist_to_print)
        printer_vuln(newlist_printable, vulnerability_name, vulnerability_description, vulnerability_recommendation, more_info)
        return f"Arbitrary From vulnerability found at line(s): {newlist_printable}"
    
    return None