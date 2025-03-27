# security_config.py

class SecurityAuditConfig:
    @staticmethod
    def get_vulnerability_descriptions():
        return {
            "Arbitrary From": "Allows unauthorized token transfers by bypassing restrictions on the 'from' address parameter in token transfers.",
            "Assembly": "Usage of low-level inline assembly that might bypass Solidity's security features and introduce vulnerabilities.",
            "Assert Violation": "Improper usage of assert() statements that may cause the contract to halt unexpectedly.",
            "Bad Assignment Operator": "Accidental use of assignment (=) instead of comparison (==) in conditional statements.",
            "Block Timestamp": "Reliance on block.timestamp for critical timing operations, which can be manipulated by miners.",
            "Delegate Call": "Unsafe usage of delegatecall that could allow attackers to manipulate contract storage.",
            "Dynamic Array Length": "Unbounded operations on dynamic arrays that could lead to gas limitations or DOS attacks.",
            "Floating Pragma": "Use of floating pragma versions that could lead to inconsistent bytecode deployment.",
            "Function Default Visibility": "Functions lacking explicit visibility specifiers, potentially exposing sensitive operations.",
            "Hash Collision": "Insufficient protection against hash collision attacks in mapping or hashing operations.",
            "Insecure Random Source": "Usage of predictable sources for random number generation.",
            "Integer Under/Overflow": "Arithmetic operations that could wrap around due to integer overflow or underflow.",
            "Looped Calls": "Unbounded loops that could hit gas limits or enable DOS attacks.",
            "Multiple Constructors": "Presence of multiple constructor definitions that could lead to initialization confusion.",
            "Re-Entrancy": "Vulnerable functions that can be recursively called to manipulate contract state.",
            "RTLO": "Use of right-to-left override characters that could mask malicious function names.",
            "Selfdestruct": "Presence of selfdestruct functionality that could permanently destroy the contract.",
            "Stored Credentials": "Sensitive information like private keys or passwords stored in contract storage.",
            "Strict Equality": "Use of strict equality comparisons that might fail for certain token implementations.",
            "Tx Origin": "Usage of tx.origin for authorization, which is vulnerable to phishing attacks.",
            "Unchecked External Call": "External calls without proper success checking or error handling.",
            "Wrong Constructor Name": "Incorrectly named constructors that fail to initialize the contract properly.",
            "Deprecated Throw": "Usage of deprecated throw statement instead of modern revert(), require(), or assert()."
        }

    @staticmethod
    def get_vulnerability_recommendations():
        return {
            "Arbitrary From": """
                1. Always validate the 'from' address in token transfers
                2. Implement proper authorization checks
                3. Use OpenZeppelin's SafeERC20 library
                4. Add explicit checks for address ownership
                5. Implement role-based access control
            """,
            "Assembly": """
                1. Avoid inline assembly unless absolutely necessary
                2. Document all assembly code thoroughly
                3. Use established libraries instead of custom assembly
                4. Conduct thorough testing of assembly code
                5. Consider higher-level Solidity alternatives
            """,
            "Assert Violation": """
                1. Use require() for input validation
                2. Reserve assert() for invariant checking
                3. Implement proper error handling
                4. Add detailed error messages
                5. Consider using custom error types
            """,
            "Bad Assignment Operator": """
                1. Use automated linting tools
                2. Implement comprehensive test coverage
                3. Use explicit comparison operators
                4. Consider using strict equality when appropriate
                5. Add comments for complex conditions
            """,
            "Block Timestamp": """
                1. Avoid reliance on block.timestamp for randomness
                2. Use time deltas instead of absolute timestamps
                3. Include reasonable timestamp margins
                4. Consider using block numbers for timing
                5. Implement oracle solutions for critical timing
            """,
            "Delegate Call": """
                1. Avoid delegatecall to untrusted contracts
                2. Implement strict address whitelisting
                3. Use proxy patterns carefully
                4. Validate target contract code
                5. Consider immutable implementations
            """,
            "Dynamic Array Length": """
                1. Implement array length limits
                2. Use pagination for large arrays
                3. Validate array inputs
                4. Consider gas costs in operations
                5. Implement batch processing
            """,
            "Floating Pragma": """
                1. Use fixed pragma versions
                2. Specify exact compiler version
                3. Document compiler requirements
                4. Test with multiple versions
                5. Consider compatibility implications
            """,
            "Function Default Visibility": """
                1. Explicitly declare all function visibilities
                2. Use private by default
                3. Audit public/external functions
                4. Document visibility decisions
                5. Implement access controls
            """,
            "Hash Collision": """
                1. Use strong hashing algorithms
                2. Implement collision resistance
                3. Validate input data
                4. Consider using unique identifiers
                5. Implement proper key management
            """,
            "Insecure Random Source": """
                1. Use Chainlink VRF for randomness
                2. Implement commit-reveal schemes
                3. Avoid block attributes for randomness
                4. Consider multi-block entropy
                5. Use secure PRNG implementations
            """,
            "Integer Under/Overflow": """
                1. Use SafeMath library
                2. Implement value bounds checking
                3. Use appropriate integer types
                4. Add overflow checks
                5. Consider using OpenZeppelin's SafeCast
            """,
            "Looped Calls": """
                1. Implement iteration limits
                2. Use pull over push patterns
                3. Implement batch processing
                4. Consider gas limitations
                5. Add emergency circuit breakers
            """,
            "Multiple Constructors": """
                1. Use single constructor pattern
                2. Implement initialization functions
                3. Use factory patterns
                4. Document initialization flow
                5. Add initialization guards
            """,
            "Re-Entrancy": """
                1. Use ReentrancyGuard modifier
                2. Implement CEI pattern
                3. Update state before external calls
                4. Use pull over push patterns
                5. Add reentrancy locks
            """,
            "RTLO": """
                1. Validate function names
                2. Use automated scanning tools
                3. Implement character filters
                4. Add name validation
                5. Consider function naming conventions
            """,
            "Selfdestruct": """
                1. Remove selfdestruct if unnecessary
                2. Implement strict access controls
                3. Add time locks
                4. Consider upgrade patterns
                5. Document destruction conditions
            """,
            "Stored Credentials": """
                1. Never store private keys on-chain
                2. Use secure off-chain storage
                3. Implement proper encryption
                4. Use access control patterns
                5. Consider using oracles
            """,
            "Strict Equality": """
                1. Use SafeERC20 for token operations
                2. Implement proper comparison checks
                3. Consider token decimals
                4. Add tolerance thresholds
                5. Use safe comparison libraries
            """,
            "Tx Origin": """
                1. Use msg.sender instead of tx.origin
                2. Implement proper authentication
                3. Add multi-factor auth
                4. Consider using signatures
                5. Implement role-based access
            """,
            "Unchecked External Call": """
                1. Always check return values
                2. Use require() for validation
                3. Implement try/catch patterns
                4. Add proper error handling
                5. Consider using call() with value check
            """,
            "Wrong Constructor Name": """
                1. Use constructor keyword
                2. Remove function-style constructors
                3. Implement proper initialization
                4. Add initialization checks
                5. Consider factory patterns
            """,
            "Deprecated Throw": """
                1. Replace throw with revert()
                2. Use require() for validation
                3. Implement proper error handling
                4. Add detailed error messages
                5. Consider custom errors
            """
        }

    @staticmethod
    def get_severity_levels():
        return {
                "Arbitrary From": "HIGH",  # Allows unauthorized transfers, major security risk
                "Assembly": "MEDIUM",  # Can introduce vulnerabilities but isn't inherently dangerous
                "Assert Violation": "LOW",  # `assert()` should only be used for internal checks
                "Bad Assignment Operator": "HIGH",  # Can lead to critical logic errors
                "Block Timestamp": "MEDIUM",  # Miners can manipulate timestamps slightly
                "Delegate Call": "CRITICAL",  # Can lead to complete contract takeover if misused
                "Dynamic Array Length": "MEDIUM",  # Could cause DoS issues but not critical
                "Floating Pragma": "LOW",  # Security risk if compiler updates introduce bugs
                "Function Default Visibility": "CRITICAL",  # Unintentional public functions can be catastrophic
                "Hash Collision": "MEDIUM",  # Rare but possible attack vector
                "Insecure Random Source": "HIGH",  # On-chain randomness can be manipulated
                "Integer Under/Overflow": "CRITICAL",  # Can lead to massive token or fund losses
                "Looped Calls": "MEDIUM",  # Gas limit issues but not always exploitable
                "Multiple Constructors": "MEDIUM",  # Can cause unintended behavior
                "Re-Entrancy": "CRITICAL",  # One of the most dangerous vulnerabilities
                "RTLO": "MEDIUM",  # Phishing risk but not a direct exploit
                "Selfdestruct": "HIGH",  # Can be used to drain contract funds
                "Stored Credentials": "CRITICAL",  # Storing private keys on-chain is a disaster
                "Strict Equality": "LOW",  # Mostly a logic bug, not always security-relevant
                "Tx Origin": "HIGH",  # Can be used to steal user funds in phishing attacks
                "Unchecked External Call": "HIGH",  # Can lead to unexpected reverts or failures
                "Wrong Constructor Name": "LOW",  # Only affects older Solidity versions
                "Deprecated Throw": "LOW"  # `revert()` replaced it, not a major security risk
        }
