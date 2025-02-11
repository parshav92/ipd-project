import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.funcdefvis import *

def function_default_visibility(contract):
    r = re.compile(r'.*function .*\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))
    
    newlist_to_print = []
    for line in newlist:
        try:
            found = re.search(r'function .*(.*?).*', line).group(0)
            splited_words = found.split()
            if len(splited_words) < 3 or splited_words[2] not in ['public', 'private', 'external', 'internal', 'public{', 'private{', 'external{', 'internal{']:
                line_number = 1 + parsed_contract_into_list.index(line)
                newlist_to_print.append(str(line_number))
        except AttributeError:
            pass
    
    newlist_printable = ', '.join(newlist_to_print)
    if newlist_printable:
        printer_vuln(newlist_printable, vulnerability_name, vulnerability_description, vulnerability_recommendation, more_info)
        return f"Function Default Visibility issue found at line(s): {newlist_printable}"
    
    return None  # Raise exception for consistent logging
