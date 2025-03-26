import click
import re
from modules.utils.parse_contract_util import parse_contract
from modules.utils.printer import printer_vuln_whole_contract
from vulnerabilities_descriptions.integer_underflow_overflow_desc import *

def integer_underflow_overflow(contract):
    """
    Detects potential integer underflow/overflow vulnerabilities in the smart contract.
    """
    # Match pragma solidity version
    r = re.compile(r'pragma solidity .*(.*)')
    parsed_contract_into_list = parse_contract(contract)

    # Exit if the parsed contract is empty
    if not parsed_contract_into_list:
        return None  # Explicitly return None

    # Filter lines matching the regex for pragma solidity
    newlist = list(filter(r.match, parsed_contract_into_list))

    if not newlist:
        return None  # Exit if no pragma line is found

    try:
        # Extract version number
        match = re.findall(r"([0-9]+[.]+[0-9]+[.]+[0-9]+)", newlist[0])
        if not match:
            return None  # Exit if no version number is found

        version = match[0]  # Example: "0.8.15"
        major_version = int(version.split('.')[1])  # Extract the second digit for comparison

        if major_version >= 8:
            return None  # Solidity 0.8.x and above handles underflow/overflow by default
        else:
            # Check for SafeMath usage in older Solidity versions
            r2 = re.compile(r'.*using SafeMath for.*')
            newlist2 = list(filter(r2.match, parsed_contract_into_list))

            if not newlist2:
                # No SafeMath found; flag the entire contract as vulnerable
                printer_vuln_whole_contract(
                    vulnerability_name,
                    vulnerability_description,
                    vulnerability_recommendation,
                    more_info
                )

                return "Integer Underflow/Overflow vulnerability detected in the contract."
    
    except IndexError:
        # Handle unexpected index errors gracefully
        return None  # Explicitly return None
