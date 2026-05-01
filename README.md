# Simple Vulnerability Scanner (Python)

A lightweight Python tool that scans a project folder for common security issues such as hardcoded secrets, insecure code, and vulnerable dependencies.

## Overview

This project is a Python-based vulnerability scanner designed to simulate real-world DevSecOps workflows. It performs automated analysis of source code and dependencies, then generates structured reports for easy review.

## Features

- Detects hardcoded secrets (passwords, API keys, AWS keys)
- Scans Python code using Bandit
- Identifies vulnerable dependencies using pip-audit
- Severity classification (HIGH, MEDIUM, LOW)
- Recursively scans project directories
- Ignores common folders (.git, venv, node_modules)
📄 Generates reports:
    - report.json (machine-readable)
    - report.html (human-readable)

## Technologies Used

- Python 3
- Bandit
- pip-audit

## Installation

Clone the repository:

git clone https://github.com/yourusername/vuln-scanner.git
cd vuln-scanner

Create and activate a virtual environment (optional but recommended):

```python -m venv .venv```
### Windows
.venv\Scripts\activate

### macOS/Linux
source .venv/bin/activate

Install dependencies:

```pip install bandit pip-audit```

## Usage

```Run the scanner:```

```python vuln_scanner.py```

```Enter the target folder:```

```Enter folder to scan: .```

## Output

After execution, the following files are generated:

```report.json```
```report.html```

## JSON Report

Structured output suitable for automation or further analysis

## HTML Report

A visual report with color-coded severity levels:

- HIGH
- MEDIUM
- LOW

## Example

```password = "123456"```
```api_key = "test_key"```

```Detected output:```

```[HIGH] Password found in test.py:1```
```[MEDIUM] API Key found in test.py:2```

## Project Structure

```vuln-scanner/ │── vuln_scanner.py │── README.md │── report.json │── report.html```