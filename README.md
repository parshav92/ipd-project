# Vulnerability Scanner for Smart Contracts

A comprehensive security scanner for Solidity smart contracts that detects common vulnerabilities and generates detailed reports.

## Setup Instructions

### Prerequisites

- Python 3.7 or higher
- Git (optional, for cloning)

### Installation

#### 1. Create Virtual Environment

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**

```cmd
python -m venv venv
venv\Scripts\activate
```

#### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
python main.py scan <contract_file.sol>
```

### Scan with PDF Output

```bash
python main.py scan <contract_file.sol> --output-pdf
```

### Examples

```bash
# Scan a contract
python main.py scan test_contracts/reentrancy.sol

# Scan and generate PDF report
python main.py scan test_contracts/ether_lotto.sol --output-pdf
```

## Features

- **20+ Vulnerability Checks** including:
  - Re-entrancy attacks
  - Integer overflow/underflow
  - Unchecked external calls
  - Delegate call vulnerabilities
  - And more...

- **PDF Report Generation** with detailed vulnerability descriptions
- **Progress Bar** for scan status
- **Colored Output** for better readability

## Output

Scan results are displayed in the terminal and optionally saved as PDF reports in the `scans/` directory.

## Test Contracts

Sample vulnerable contracts are provided in the `test_contracts/` directory for testing the scanner.

## Deactivating Virtual Environment

```bash
deactivate
```
