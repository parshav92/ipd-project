import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import *
from vulnerabilities_descriptions.assertviol_desc import *


def assert_violation(contract):
    r = re.compile(r'^.*assert\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))
    
    if newlist:
        newlist_to_print = [str(1 + parsed_contract_into_list.index(line)) for line in newlist]
        newlist_printable = ', '.join(newlist_to_print)
        printer_vuln(newlist_printable, vulnerability_name, vulnerability_description, vulnerability_recommendation, more_info)
        return f"Assert Violation found at line(s): {newlist_printable}"
    
    return None
