vulnerability_name = "Assembly"

vulnerability_description = """
Inline assembly is a way to write assembly-level code in Solidity. 
While it gives precise control over the EVM, it bypasses several 
important safety features of Solidity and can lead to vulnerabilities 
if not used carefully.
"""

vulnerability_recommendation = """
1. Avoid using inline assembly unless absolutely necessary
2. If assembly is required, thoroughly document the code
3. Use established libraries instead of custom assembly code
4. Always have assembly code reviewed by multiple auditors
5. Consider higher-level Solidity alternatives
"""

more_info = [
    "https://docs.soliditylang.org/en/latest/assembly.html",
    "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/assembly/",
    "https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage"
]