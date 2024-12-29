import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.reentrancy_desc import *

def reentrancy(contract):
    r = re.compile(r'^.*call\.value\(.*\).*')
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))

    newlist_to_print = []
    if newlist:
        for item in newlist:
            line_number = 1 + parsed_contract_into_list.index(item)
            newlist_to_print.append(str(line_number))

        newlist_printable = ', '.join(newlist_to_print)
        printer_vuln(
            newlist_printable,
            "Re-Entrancy",
            "Re-entrant calls are detected.",
            "Use a re-entrancy guard or ensure external calls are made at the end of the function.",
            ["https://consensys.github.io/smart-contract-best-practices/known_attacks/#reentrancy"]
        )
