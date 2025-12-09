# Heady

HEADY is a Python-based CLI tool for scanning HTTP response security headers.
It detects missing headers, validates header configuration, assigns severity,
and optionally exports reports for further analysis.

The tool is designed to run cleanly on Windows and Linux terminals.

## Features

- Command-line interface with banner and scan status
- Fetches HTTP(S) response headers
- Detects missing security headers
- Validates configuration of present headers
- Status per header:
  - OK
  - WARN
  - FAIL
  - MISSING
- Severity levels:
  - HIGH
  - MEDIUM
  - LOW
  - INFO
- Optional report export:
  - Text
  - CSV
  - Excel
- Meaningful exit codes for automation and CI usage

## Supported Security Headers

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Resource-Policy (CORP)
- Cross-Origin-Opener-Policy (COOP)
- X-XSS-Protection (legacy, informational)

## Project Structure
heady/
├── heady/
│ ├── init.py
│ └── sec_headers_scan.py
├── pyproject.toml
├── requirements.txt
└── README.md

## Installation

```
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Usage

```
heady https://example.com
```

## Export Reports

Only one export format can be selected per run.

### Text

heady https://example.com -text

markdown
Copy code

Creates:
- `shs_report_<hostname>.txt`

### CSV

heady https://example.com -csv

markdown
Copy code

Creates:
- `shs_report_<hostname>.csv`

### Excel

heady https://example.com -excel

yaml
Copy code

Creates:
- `shs_report_<hostname>.xlsx`

Excel export requires:
- pandas
- openpyxl

## Exit Codes

- 0  
  All HIGH and MEDIUM severity headers are present and not marked FAIL.

- 1  
  One or more HIGH or MEDIUM severity headers are MISSING or FAIL.

This makes HEADY suitable for CI/CD pipelines and automated security checks.

## Notes

- HEADY analyzes HTTP response headers only.
- It does not inspect HTML meta tags, JavaScript, or browser runtime behavior.
- Results represent header-level security posture, not full application security.

## License

MIT License