from hashlib import new
import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.selfdestruct_desc import *

def selfdestruct(contract):
    r = re.compile(r'^.*selfdestruct\(.*\).*|^.*suicide\(.*\).*')  # Add raw string prefix
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))

    newlist_to_print = []

    if newlist:
        for i in range(len(newlist)):
            line_number = 1 + parsed_contract_into_list.index(newlist[i])  # Line number
            line_number_as_str = str(line_number)  # Convert to string
            newlist_to_print.append(line_number_as_str)  # Store in list
        
        newlist_printable = ', '.join(newlist_to_print)  # Format as string
        
        # Use printer
        printer_vuln(newlist_printable, vulnerability_name, vulnerability_description, vulnerability_recommendation, more_info)

        return f"Selfdestruct vulnerability found at line(s): {newlist_printable}"
    
    return None  # Explicitly return None if no vulnerabilities found