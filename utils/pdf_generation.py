from fpdf import FPDF

def save_results_to_pdf(results, output_file="scan_results.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(200, 10, txt="Smart Contract Scan Results", ln=True, align='C')
    pdf.ln(5)

    # Subtitle
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Detailed Vulnerability Report", ln=True, align='C')
    pdf.ln(10)

    # Table Header
    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(80, 10, "Vulnerability", border=1, align='C')
    pdf.cell(110, 10, "Result", border=1, align='C')
    pdf.ln()

    pdf.set_font("Arial", size=10)

    vulnerability_descriptions = {
        "Arbitrary From": "Allows unauthorized token transfers by bypassing restrictions.",
        "Assembly": "Potentially unsafe low-level assembly code usage.",
        "Assert Violation": "Incorrect assert usage may cause unintended contract behavior.",
        "Bad Assignment Operator": "Using `=` instead of `==` in conditions can introduce logic errors.",
        "Block Timestamp": "Block timestamp manipulation may allow unfair advantage in smart contracts.",
        "Delegate Call": "Delegate calls can introduce security risks if the callee is untrusted.",
        "Dynamic Array Length": "Improper dynamic array management can lead to out-of-bounds errors.",
        "Floating Pragma": "Unpinned Solidity versions may lead to unintended compiler differences.",
        "Function Default Visibility": "Functions without explicit visibility may be unintentionally exposed.",
        "Hash Collision": "Weak hashing algorithms can lead to security vulnerabilities.",
        "Insecure Random Source": "Randomness derived from block properties is predictable.",
        "Integer Under/Overflow": "Arithmetic operations can wrap around, causing unexpected behavior.",
        "Looped Calls": "Uncontrolled recursion can lead to DoS attacks.",
        "Multiple Constructors": "Having multiple constructors can create unintended contract states.",
        "Re-Entrancy": "A contract function calling itself before completion can drain funds.",
        "RTLO": "Right-to-left override characters can be used for deceptive function naming.",
        "Selfdestruct": "Contracts that self-destruct can remove critical functionality.",
        "Stored Credentials": "Sensitive credentials found in contract storage.",
        "Strict Equality": "Strict equality checks may cause unexpected behavior.",
        "Tx Origin": "Using `tx.origin` instead of `msg.sender` can expose the contract to phishing attacks.",
        "Unchecked External Call": "Failure to verify external call results can lead to vulnerabilities.",
        "Wrong Constructor Name": "Incorrect constructor names in older Solidity versions can cause issues.",
        "Deprecated Throw": "`throw` is deprecated; `revert()` or `require()` should be used instead.",
    }

    for line in results:
        if ": " in line:
            check_name, result = line.split(": ", 1)
            description = vulnerability_descriptions.get(check_name, "No description available.")
            
            # Print vulnerability name
            pdf.set_font("Arial", style="B", size=11)
            pdf.multi_cell(0, 8, f"{check_name}", border='B')

            # Print description
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 6, f"Description: {description}")

            # Print result
            pdf.set_font("Arial", style="B", size=10)
            if "FAILED" in result:
                pdf.set_text_color(255, 0, 0)  # Red
            elif "PASSED" in result:
                pdf.set_text_color(0, 128, 0)  # Green
            else:
                pdf.set_text_color(0, 0, 255)  # Blue
            
            pdf.multi_cell(0, 6, f"Result: {result}")
            pdf.set_text_color(0, 0, 0)  # Reset color
            pdf.ln(3)  # Add spacing between sections

    pdf.output(output_file)
    print(f"Results saved to {output_file}")
