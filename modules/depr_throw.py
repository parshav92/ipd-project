import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln  # Updated import
from vulnerabilities_descriptions.throw_desc import *

def throw(contract):
    r = re.compile('^.*throw.*')
    parsed_contract_into_list = parse_contract(contract)
    newlist = list(filter(r.match, parsed_contract_into_list))

    newlist_to_print = []
    if newlist:
        for item in newlist:
            line_number = 1 + parsed_contract_into_list.index(item)  # line number
            newlist_to_print.append(str(line_number))  # line number to string

        newlist_printable = ', '.join(newlist_to_print)  # list to printable
        # Use printer
        printer_vuln(
            newlist_printable,
            "Deprecated Throw",
            "The 'throw' statement is deprecated.",
            "Replace 'throw' with 'revert' or 'require' to make the code compliant with modern Solidity.",
            ["https://solidity.readthedocs.io/en/v0.4.21/control-structures.html#error-handling-assert-require-revert-and-exceptions"]
        )
    else:
        return