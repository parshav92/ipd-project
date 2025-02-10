import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import *
from vulnerabilities_descriptions.unchecked_external_call_desc import *

def unchecked_external_call(contract):
    r = re.compile(r'^.*\.send\(.*\).*')  # Detects `send()` usage
    parsed_contract_into_list = parse_contract(contract)
    detected_lines = [str(i+1) for i, line in enumerate(parsed_contract_into_list) if r.match(line)]

    if detected_lines:
        newlist_printable = ', '.join(detected_lines)
        
        # Print to CLI using printer_vuln
        printer_vuln(newlist_printable, vulnerability_name, vulnerability_description, vulnerability_recommendation, more_info)
        
        # Return the result for logging
        return f"Unchecked external call vulnerability found at line(s): {newlist_printable}"
    
    return None  # No vulnerabilities found
