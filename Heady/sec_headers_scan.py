#!/usr/bin/env python3

import argparse
import sys
import re
import csv
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Callable
from urllib.parse import urlparse
from pathlib import Path

import requests

try:
    import pandas as pd  # for Excel support
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


# ---------------------- Data structures ---------------------- #

@dataclass
class HeaderRule:
    name: str
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    description: str
    validator: Optional[Callable[[str, str], Tuple[str, str]]] = None


@dataclass
class HeaderResult:
    rule: HeaderRule
    status: str  # "MISSING", "OK", "WARN", "FAIL"
    message: str
    value: Optional[str]


# ---------------------- Validators ---------------------- #

def validate_hsts(value: str, url: str) -> Tuple[str, str]:
    v = value.strip()
    v_lower = v.lower()

    if not url.lower().startswith("https://"):
        return "FAIL", "HSTS is only effective over HTTPS; current URL is not HTTPS."

    if "max-age" not in v_lower:
        return "FAIL", "Missing max-age directive in HSTS."

    m = re.search(r"max-age\s*=\s*(\d+)", v_lower)
    if not m:
        return "FAIL", "Could not parse max-age in HSTS."

    max_age = int(m.group(1))
    issues = []

    if max_age < 15552000:  # 180 days
        issues.append("max-age is less than 15552000 (180 days).")

    if "includesubdomains" not in v_lower:
        issues.append("includeSubDomains is not set.")

    if issues:
        return "WARN", "; ".join(issues)

    return "OK", "HSTS configuration looks reasonable."


def validate_x_content_type_options(value: str, url: str) -> Tuple[str, str]:
    v = value.strip().lower()
    if v == "nosniff":
        return "OK", "X-Content-Type-Options is correctly set to nosniff."
    return "FAIL", f"Expected 'nosniff', got '{value}'."


def validate_x_frame_options(value: str, url: str) -> Tuple[str, str]:
    v = value.strip().lower()
    if v in ("deny", "sameorigin"):
        return "OK", f"X-Frame-Options is set to {v}."
    return "WARN", f"Non-standard X-Frame-Options value: '{value}'. Prefer DENY or SAMEORIGIN."


def validate_referrer_policy(value: str, url: str) -> Tuple[str, str]:
    v = value.strip().lower()
    good = {
        "no-referrer",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
    }
    weak = {
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
    }

    if v in good:
        return "OK", f"Referrer-Policy set to '{v}', considered strong."
    if v in weak:
        return "WARN", f"Referrer-Policy '{v}' is weaker; consider stricter options."
    return "WARN", f"Unrecognized Referrer-Policy value: '{value}'."


def validate_csp(value: str, url: str) -> Tuple[str, str]:
    v = value.strip()
    if not v:
        return "FAIL", "CSP header is empty."

    v_lower = v.lower()
    issues = []

    if "unsafe-inline" in v_lower:
        issues.append("Uses 'unsafe-inline' which weakens XSS protection.")
    if "unsafe-eval" in v_lower:
        issues.append("Uses 'unsafe-eval' which weakens XSS protection.")
    if "*" in v_lower and "default-src" in v_lower:
        issues.append("Default source allows '*', which is overly permissive.")

    if issues:
        return "WARN", "; ".join(issues)

    return "OK", "CSP present and no obvious weak patterns detected."


def validate_permissions_policy(value: str, url: str) -> Tuple[str, str]:
    v = value.strip()
    if not v:
        return "WARN", "Permissions-Policy is empty."
    return "OK", "Permissions-Policy present (detailed parse not implemented)."


def validate_corp(value: str, url: str) -> Tuple[str, str]:
    v = value.strip().lower()
    if v in ("same-origin", "same-site"):
        return "OK", f"CORP set to '{v}'."
    if v == "cross-origin":
        return "WARN", "CORP 'cross-origin' is permissive; consider same-origin or same-site."
    return "WARN", f"Unrecognized CORP value: '{value}'."


def validate_coop(value: str, url: str) -> Tuple[str, str]:
    v = value.strip().lower()
    if v == "same-origin":
        return "OK", "COOP set to 'same-origin'."
    if v == "same-origin-allow-popups":
        return "WARN", "COOP 'same-origin-allow-popups' is weaker; evaluate necessity."
    return "WARN", f"Unrecognized COOP value: '{value}'."


def validate_x_xss_protection(value: str, url: str) -> Tuple[str, str]:
    v = value.strip().lower()
    if v == "0":
        return "OK", "X-XSS-Protection disabled (modern recommended approach, rely on CSP)."
    if v.startswith("1"):
        return "WARN", f"Legacy X-XSS-Protection in use: '{value}'. Prefer CSP-based defenses."
    return "WARN", f"Unexpected X-XSS-Protection value: '{value}'."


# ---------------------- Header rules ---------------------- #

SECURITY_HEADERS: Dict[str, HeaderRule] = {
    "Strict-Transport-Security": HeaderRule(
        name="Strict-Transport-Security",
        severity="HIGH",
        description="Enforces HTTPS and helps prevent protocol downgrade and cookie hijacking.",
        validator=validate_hsts,
    ),
    "Content-Security-Policy": HeaderRule(
        name="Content-Security-Policy",
        severity="HIGH",
        description="Mitigates XSS and data injection by whitelisting trusted content sources.",
        validator=validate_csp,
    ),
    "X-Content-Type-Options": HeaderRule(
        name="X-Content-Type-Options",
        severity="MEDIUM",
        description="Prevents MIME type sniffing; should be set to 'nosniff'.",
        validator=validate_x_content_type_options,
    ),
    "X-Frame-Options": HeaderRule(
        name="X-Frame-Options",
        severity="MEDIUM",
        description="Mitigates clickjacking by controlling framing of the site.",
        validator=validate_x_frame_options,
    ),
    "Referrer-Policy": HeaderRule(
        name="Referrer-Policy",
        severity="MEDIUM",
        description="Controls how much referrer information is sent in requests.",
        validator=validate_referrer_policy,
    ),
    "Permissions-Policy": HeaderRule(
        name="Permissions-Policy",
        severity="LOW",
        description="Restricts powerful browser features (camera, mic, geolocation, etc.).",
        validator=validate_permissions_policy,
    ),
    "Cross-Origin-Resource-Policy": HeaderRule(
        name="Cross-Origin-Resource-Policy",
        severity="LOW",
        description="Helps protect resources from being loaded by other origins.",
        validator=validate_corp,
    ),
    "Cross-Origin-Opener-Policy": HeaderRule(
        name="Cross-Origin-Opener-Policy",
        severity="LOW",
        description="Isolates browsing context groups to improve security.",
        validator=validate_coop,
    ),
    "X-XSS-Protection": HeaderRule(
        name="X-XSS-Protection",
        severity="INFO",
        description="Legacy XSS filter header; modern defense is CSP, but still tracked.",
        validator=validate_x_xss_protection,
    ),
}


# ---------------------- Core logic ---------------------- #

def print_banner():
    title = " SHS - Security Header Scanner "
    width = max(60, len(title) + 4)
    print("+" + "-" * (width - 2) + "+")
    print("|" + title.center(width - 2) + "|")
    print("+" + "-" * (width - 2) + "+")


def fetch_headers(url: str, timeout: int = 10) -> Tuple[Dict[str, str], str]:
    try:
        print("[*] scan begins")
        print("[*] fetching headers...")
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        print("[*] headers received")
    except requests.exceptions.RequestException as e:
        print(f"[!] error fetching {url}: {e}", file=sys.stderr)
        sys.exit(1)

    headers = {k.strip(): v.strip() for k, v in resp.headers.items()}
    return headers, resp.url


def analyze_headers(headers: Dict[str, str], final_url: str) -> List[HeaderResult]:
    print("[*] analyzing security headers...")
    results: List[HeaderResult] = []
    header_keys_lower = {k.lower(): k for k in headers.keys()}

    for rule_name, rule in SECURITY_HEADERS.items():
        lower_name = rule_name.lower()
        if lower_name in header_keys_lower:
            actual_name = header_keys_lower[lower_name]
            value = headers[actual_name]
            if rule.validator:
                status, msg = rule.validator(value, final_url)
            else:
                status, msg = "OK", "Present (no validator implemented)."
            results.append(HeaderResult(rule=rule, status=status, message=msg, value=value))
        else:
            results.append(
                HeaderResult(
                    rule=rule,
                    status="MISSING",
                    message=f"{rule.name} header is missing.",
                    value=None,
                )
            )

    missing = [r for r in results if r.status == "MISSING"]
    print(f"[*] {len(missing)} tracked security headers missing")
    print("[*] done")
    return results


def build_text_report(url: str, final_url: str, headers: Dict[str, str], results: List[HeaderResult]) -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append(f"Security Header Scan for: {url}")
    if final_url != url:
        lines.append(f"(Final URL after redirects: {final_url})")
    lines.append("=" * 80)

    lines.append("")
    lines.append("[+] Response Headers:")
    for k, v in headers.items():
        lines.append(f"    {k}: {v}")

    lines.append("")
    lines.append("[+] Detailed Security Header Analysis:")
    for r in results:
        value_part = f"Value: {r.value}" if r.value is not None else "Value: <absent>"
        lines.append(f"    [{r.rule.severity}] {r.rule.name}")
        lines.append(f"        Status: {r.status}")
        lines.append(f"        {value_part}")
        lines.append(f"        Info: {r.message}")

    missing = [r for r in results if r.status == "MISSING"]
    warn_or_fail = [r for r in results if r.status in ("WARN", "FAIL")]

    lines.append("")
    lines.append("[+] Summary:")
    if missing:
        lines.append("    Missing headers:")
        for r in missing:
            lines.append(f"        [{r.rule.severity}] {r.rule.name} - {r.message}")
    else:
        lines.append("    No tracked headers are completely missing.")

    if warn_or_fail:
        lines.append("")
        lines.append("    Misconfigured / weak headers:")
        for r in warn_or_fail:
            prefix = "WARN" if r.status == "WARN" else "FAIL"
            lines.append(f"        [{r.rule.severity}] {r.rule.name} - {prefix}: {r.message}")
    else:
        lines.append("")
        lines.append("    No obvious misconfigurations detected in tracked headers.")

    high_med_issues = [
        r for r in results
        if r.rule.severity in ("HIGH", "MEDIUM")
        and r.status in ("MISSING", "FAIL")
    ]
    lines.append("")
    if high_med_issues:
        lines.append("[-] Result: HIGH/MEDIUM severity issues detected (missing or failed).")
    else:
        lines.append("[+] Result: All HIGH/MEDIUM headers present and not critically misconfigured.")

    return "\n".join(lines)


def print_report_to_console(report_text: str):
    print()
    print(report_text)


def write_text_file(path: Path, report_text: str):
    path.write_text(report_text, encoding="utf-8")
    print(f"[+] text report saved to: {path}")


def write_csv_file(path: Path, url: str, final_url: str, results: List[HeaderResult]):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "final_url", "header_name", "severity", "status", "value", "message"])
        for r in results:
            writer.writerow([
                url,
                final_url,
                r.rule.name,
                r.rule.severity,
                r.status,
                r.value or "",
                r.message,
            ])
    print(f"[+] csv report saved to: {path}")


def write_excel_file(path: Path, url: str, final_url: str, results: List[HeaderResult]):
    if not HAS_PANDAS:
        print("[!] Excel export requested but pandas is not installed. Install with:")
        print("    pip install pandas openpyxl")
        return

    rows = []
    for r in results:
        rows.append({
            "url": url,
            "final_url": final_url,
            "header_name": r.rule.name,
            "severity": r.rule.severity,
            "status": r.status,
            "value": r.value or "",
            "message": r.message,
        })
    df = pd.DataFrame(rows)
    df.to_excel(path, index=False)
    print(f"[+] excel report saved to: {path}")


def print_and_save_reports(
    url: str,
    final_url: str,
    headers: Dict[str, str],
    results: List[HeaderResult],
    output_format: Optional[str],
):
    report_text = build_text_report(url, final_url, headers, results)
    print_report_to_console(report_text)

    if not output_format:
        return

    parsed = urlparse(final_url or url)
    host = parsed.hostname or "output"
    base_name = f"shs_report_{host}"

    if output_format == "text":
        path = Path(f"{base_name}.txt")
        write_text_file(path, report_text)
    elif output_format == "csv":
        path = Path(f"{base_name}.csv")
        write_csv_file(path, url, final_url, results)
    elif output_format == "excel":
        path = Path(f"{base_name}.xlsx")
        write_excel_file(path, url, final_url, results)


def compute_exit_code(results: List[HeaderResult]) -> int:
    high_med_issues = [
        r for r in results
        if r.rule.severity in ("HIGH", "MEDIUM")
        and r.status in ("MISSING", "FAIL")
    ]
    return 1 if high_med_issues else 0


# ---------------------- CLI parsing ---------------------- #

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="HTTP security header scanner with configuration checks and export."
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g. https://example.com)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-text",
        dest="output_format",
        action="store_const",
        const="text",
        help="Save report as a text file.",
    )
    group.add_argument(
        "-csv",
        dest="output_format",
        action="store_const",
        const="csv",
        help="Save report as a CSV file.",
    )
    group.add_argument(
        "-excel",
        dest="output_format",
        action="store_const",
        const="excel",
        help="Save report as an Excel (.xlsx) file.",
    )

    return parser.parse_args(argv)


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url


def main(argv=None):
    args = parse_args(argv)

    print_banner()

    url = normalize_url(args.url)
    print(f"[*] target: {url}")

    headers, final_url = fetch_headers(url, timeout=args.timeout)
    results = analyze_headers(headers, final_url)

    print_and_save_reports(
        url=url,
        final_url=final_url,
        headers=headers,
        results=results,
        output_format=args.output_format,
    )

    exit_code = compute_exit_code(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
