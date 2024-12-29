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

# Initialize colorama
init(autoreset=True)

# PDF generation function
def save_results_to_pdf(results, output_file="scan_results.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Smart Contract Scan Results", ln=True, align='C')
    pdf.ln(10)  # Add a line break

    for line in results:
        pdf.multi_cell(0, 10, txt=line)
    
    pdf.output(output_file)
    print(f"Results saved to {output_file}")

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

    def log_result(check_name, func):
        try:
            func(contract)
            results.append(f"{check_name}: PASSED")
        except Exception as e:
            results.append(f"{check_name}: FAILED - {str(e)}")

    # Perform vulnerability checks
    log_result("Arbitrary From", arbitraryfrom)
    log_result("Assembly", assembly)
    log_result("Assert Violation", assert_violation)
    log_result("Bad Assignment Operator", bad_assignment_operator)
    log_result("Block Timestamp", block_timestamp)
    log_result("Delegate Call", delegate_call)
    log_result("Dynamic Array Length", dynamic_array_length)
    log_result("Floating Pragma", floating_pragma)
    log_result("Function Default Visibility", function_default_visibility)
    log_result("Hash Collision", hash_colission)
    log_result("Insecure Random Source", randomsource)
    log_result("Integer Under/Overflow", integer_underflow_overflow)
    log_result("Looped Calls", looped_calls)
    log_result("Multiple Constructors", multiple_constructors)
    log_result("Re-Entrancy", reentrancy)
    log_result("RTLO", rtlo)
    log_result("Selfdestruct", selfdestruct)
    log_result("Stored Credentials", stored_credentials)
    log_result("Strict Equality", strict_equality)
    log_result("Tx Origin", tx_origin)
    log_result("Unchecked External Call", unchecked_external_call)
    log_result("Wrong Constructor Name", wrong_constructor_name)
    log_result("Deprecated Throw", throw)

    for line in results:
        print(line)
    
    if output_pdf:
        save_results_to_pdf(results)

    click.echo("Scan completed. See results above.")

mycommands.add_command(scan_contract)

if __name__ == '__main__':
    mycommands()
