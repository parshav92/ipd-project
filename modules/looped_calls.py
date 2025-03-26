import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln
from vulnerabilities_descriptions.loopedcalls_desc import *

def looped_calls(contract):
    """
    Detects external calls (transfer, send, call) made within loops in the smart contract.
    """
    parsed_contract_into_list = parse_contract(contract)

    # Regex to detect loops
    loop_regex = re.compile(r'\b(for|while|do)\b')

    # Regex to detect external calls
    external_call_regex = re.compile(r'\.\b(transfer|send|call)\b')

    # Detect loop lines and external call lines
    loop_lines = [line for line in parsed_contract_into_list if loop_regex.search(line)]
    call_lines = [line for line in parsed_contract_into_list if external_call_regex.search(line)]

    # Check if external calls are inside loops
    newlist_to_print = []
    for loop in loop_lines:
        loop_index = parsed_contract_into_list.index(loop)
        for call in call_lines:
            call_index = parsed_contract_into_list.index(call)
            if loop_index < call_index:  # Check if the external call is nested in the loop
                newlist_to_print.append(str(call_index + 1))  # 1-based index

    if newlist_to_print:
        newlist_printable = ', '.join(newlist_to_print)
        printer_vuln(
            newlist_printable,
            vulnerability_name,
            vulnerability_description,
            vulnerability_recommendation,
            more_info
        )
        return f"Looped Calls vulnerability found at line(s): {newlist_printable}"
    
    return None  # Explicitly return None if no vulnerabilities found
