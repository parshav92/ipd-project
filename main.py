import click
import re
import time
import sys
from fpdf import FPDF
from colorama import init, Fore, Style
from modules import insec_randomsource
from modules import re_entrancy
from modules.utils.printer import printer_vuln
# Import vulnerability modules
from modules.re_entrancy import reentrancy
from modules.insec_randomsource import randomsource
from modules.floating_pragma import *
from modules.utils.parse_contract_util import parse_contract
from modules.selfdestruct import selfdestruct
from modules.re_entrancy import * 
from modules.unchecked_external_call import * 
from modules.wrong_constructor_name import * 
from modules.stored_credentials import * 
from modules.insec_randomsource import * 
from modules.tx_origin import * 
from modules.assembly import * 
from modules.delegate_call import *
from modules.ether_lock import *
from modules.utils.remove_comments import *
from modules.integer_underflow_overflow import *
from modules.rtlo import *
from modules.multiple_constructors import *
from modules.dynamic_array_length import *
from modules.utils.banner import *
from modules.looped_calls import *
from modules.hash_colission import *
from modules.functions_default_visibility import *
from modules.assert_violation import *
from modules.arbitraryfrom import *
from modules.bad_assignment_operator import *
from modules.depr_blockhash import *
from modules.depr_msggas import *
from modules.depr_now import *
from modules.depr_sha3 import *
from modules.depr_throw import *
from modules.multidigits import *
from modules.strict_equality import *
from utils.pdf_generation import save_results_to_pdf
import os
from pathlib import Path
        
# Initialize colorama
init(autoreset=True)


# Progress bar function
def update_bar(total_length):
    for i in range(total_length + 1):
        percent_complete = int((i / total_length) * 100)
        bar = f'{Fore.GREEN}#' * i + f'{Fore.RED}-' * (total_length - i)
        sys.stdout.write(f'\r{Fore.CYAN}Running checks: [{bar}] {percent_complete}%')
        sys.stdout.flush()
        time.sleep(0.1)

    print(Style.RESET_ALL + "\nScan complete!\n")

@click.group()
def mycommands():
    pass

@click.command('scan', help="Scan a smart contract for vulnerabilities")
@click.argument('contract', type=click.Path(exists=True), required=1)
@click.option('--output-pdf', is_flag=True, help="Save the output as a PDF")
def scan_contract(contract, output_pdf):
    print_banner(contract)
    total_length = 30
    update_bar(total_length)

    results = []
    results.append("======================================")
    results.append("              RESULTS")
    results.append("======================================")

    def log_result(check_name, func, contract, results):
        """
            Logs the result of a vulnerability check to the results list.
        """
        try:
            func(contract)  # Run the vulnerability function
            results.append(f"{check_name}: PASSED")  # Mark as PASSED if no exceptions
        except Exception as e:
            if str(e) == "Vulnerability Detected":
                results.append(f"{check_name}: FAILED - Vulnerability Detected")
            else:
                results.append(f"{check_name}: ERROR - {str(e)}")  # Log unexpected errors

    # Perform vulnerability checks
    log_result("Arbitrary From", arbitraryfrom, contract, results)
    log_result("Assembly", assembly, contract, results)
    log_result("Assert Violation", assert_violation, contract, results)
    log_result("Bad Assignment Operator", bad_assignment_operator, contract, results)
    log_result("Block Timestamp", block_timestamp, contract, results)
    log_result("Delegate Call", delegate_call, contract, results)
    log_result("Dynamic Array Length", dynamic_array_length, contract, results)
    log_result("Floating Pragma", floating_pragma, contract, results)
    log_result("Function Default Visibility", function_default_visibility, contract, results)
    log_result("Hash Collision", hash_colission, contract, results)
    log_result("Insecure Random Source", randomsource, contract, results)
    log_result("Integer Under/Overflow", integer_underflow_overflow, contract, results)
    log_result("Looped Calls", looped_calls, contract, results)
    log_result("Multiple Constructors", multiple_constructors, contract, results)
    log_result("Re-Entrancy", reentrancy, contract, results)
    log_result("RTLO", rtlo, contract, results)
    log_result("Selfdestruct", selfdestruct, contract, results)
    log_result("Stored Credentials", stored_credentials, contract, results)
    log_result("Strict Equality", strict_equality, contract, results)
    log_result("Tx Origin", tx_origin, contract, results)
    log_result("Unchecked External Call", unchecked_external_call, contract, results)
    log_result("Wrong Constructor Name", wrong_constructor_name, contract, results)
    log_result("Deprecated Throw", throw, contract, results)

    for line in results:
        print(line)
    
    if output_pdf:
        scan_dir = Path('scans')
        scan_dir.mkdir(exist_ok=True)

        contract_name = Path(contract).stem
        pdf_filename = scan_dir / f"{contract_name}_scan_results.pdf"

        save_results_to_pdf(results, pdf_filename)

    click.echo("Scan completed. See results above.")


mycommands.add_command(scan_contract)

if __name__ == '__main__':
    mycommands()
