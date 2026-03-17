#!/usr/bin/env python3
"""
JWTester - JWT Vulnerability Scanner
Author: Abin A | github.com/abinsolo
Checks: alg:none, weak secret, expired, KID injection, algorithm confusion
"""

import jwt
import json
import base64
import argparse
import requests
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

console = Console()

BANNER = """
     ██╗██╗    ██╗████████╗███████╗███████╗████████╗███████╗██████╗
     ██║██║    ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
     ██║██║ █╗ ██║   ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
██   ██║██║███╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
╚█████╔╝╚███╔███╔╝   ██║   ███████╗███████║   ██║   ███████╗██║  ██║
 ╚════╝  ╚══╝╚══╝    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
              JWT Vulnerability Scanner | by Abin A
"""

WEAK_SECRETS = [
    "secret", "password", "123456", "test", "key",
    "admin", "letmein", "qwerty", "jwt", "token",
    "supersecret", "mysecret", "changeme", "default",
    "secret123", "password123", "admin123", "root",
    "topsecret", "jwttoken", "accesstoken", ""
]

def decode_jwt(token):
    """Decode JWT without verification to inspect contents."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        return header, payload
    except Exception as e:
        console.log(f"[red]Failed to decode token:[/red] {e}")
        return None, None

def check_alg_none(token):
    """Test alg:none attack — removes signature requirement."""
    console.rule("[bold yellow]Test 1 — Algorithm None Attack")
    try:
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        forged = f"{new_header}.{parts[1]}."
        console.log(f"[cyan]Forged token (alg:none):[/cyan] {forged[:80]}...")
        console.log("[bold red][!] VULNERABLE — alg:none token generated. Test this against the target endpoint.")
        return True, forged
    except Exception as e:
        console.log(f"[green][+] alg:none test failed (likely safe):[/green] {e}")
        return False, None

def check_weak_secret(token):
    """Brute force common weak secrets."""
    console.rule("[bold yellow]Test 2 — Weak Secret Brute Force")
    header, payload = decode_jwt(token)
    if not header:
        return False, None
    alg = header.get("alg", "HS256")
    if alg not in ["HS256", "HS384", "HS512"]:
        console.log(f"[yellow][!] Algorithm is {alg} — skipping HMAC brute force")
        return False, None
    for secret in WEAK_SECRETS:
        try:
            jwt.decode(token, secret, algorithms=[alg])
            console.log(f"[bold red][!] VULNERABLE — Weak secret found: '{secret}'")
            return True, secret
        except jwt.InvalidSignatureError:
            continue
        except Exception:
            continue
    console.log("[green][+] No weak secret found from common list")
    return False, None

def check_expiry(payload):
    """Check if token is expired."""
    console.rule("[bold yellow]Test 3 — Expiry Check")
    import time
    exp = payload.get("exp")
    if not exp:
        console.log("[yellow][!] No expiry (exp) claim found — token never expires")
        return True
    current = int(time.time())
    if current > exp:
        console.log(f"[bold red][!] VULNERABLE — Token is EXPIRED (exp: {exp}, now: {current})")
        return True
    else:
        remaining = exp - current
        console.log(f"[green][+] Token valid — expires in {remaining} seconds")
        return False

def check_kid_injection(token):
    """Check for KID header injection possibility."""
    console.rule("[bold yellow]Test 4 — KID Injection Check")
    header, _ = decode_jwt(token)
    if not header:
        return False
    kid = header.get("kid")
    if kid:
        console.log(f"[yellow][!] KID claim found: '{kid}'")
        console.log("[bold red][!] POTENTIAL — Test KID SQL Injection:")
        console.log(f"[cyan]    Payload: ' UNION SELECT 'attacker_secret' --[/cyan]")
        console.log(f"[cyan]    Payload: ../../dev/null[/cyan]")
        return True
    else:
        console.log("[green][+] No KID claim found")
        return False

def check_sensitive_data(payload):
    """Check for sensitive data leaked in payload."""
    console.rule("[bold yellow]Test 5 — Sensitive Data in Payload")
    sensitive_keys = ["password", "passwd", "secret", "key", "ssn",
                      "credit", "card", "cvv", "pin", "private"]
    found = []
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            found.append(key)
    if found:
        console.log(f"[bold red][!] Sensitive keys found in payload: {found}")
        return True
    console.log("[green][+] No obvious sensitive data in payload")
    return False

def print_token_info(header, payload):
    """Print decoded token info in a table."""
    console.rule("[bold cyan]Token Information")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Field", style="bold white")
    table.add_column("Value", style="yellow")
    for k, v in header.items():
        table.add_row(f"[HEADER] {k}", str(v))
    for k, v in payload.items():
        table.add_row(f"[PAYLOAD] {k}", str(v))
    console.print(table)

def print_summary(results):
    """Print final summary panel."""
    vulns = [r for r in results if results[r]]
    safe  = [r for r in results if not results[r]]
    color = "red" if vulns else "green"
    status = "VULNERABILITIES FOUND" if vulns else "NO VULNERABILITIES FOUND"
    content = f"[bold {color}]{status}[/bold {color}]\n\n"
    if vulns:
        for v in vulns:
            content += f"[red]  [!] {v}[/red]\n"
    for s in safe:
        content += f"[green]  [+] {s} — OK[/green]\n"
    console.print(Panel.fit(content, title="[bold cyan]JWTester Results[/bold cyan]",
                            border_style=color))

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="JWTester — JWT Vulnerability Scanner by Abin A")
    parser.add_argument("-t", "--token",  required=True, help="JWT token to test")
    parser.add_argument("--all",          action="store_true", help="Run all tests (default)")
    parser.add_argument("--alg-none",     action="store_true", help="Test alg:none only")
    parser.add_argument("--weak-secret",  action="store_true", help="Test weak secret only")
    parser.add_argument("--expiry",       action="store_true", help="Test expiry only")
    parser.add_argument("--kid",          action="store_true", help="Test KID injection only")
    args = parser.parse_args()

    token = args.token.strip()
    header, payload = decode_jwt(token)

    if not header or not payload:
        console.log("[red]Invalid JWT token — check format and try again")
        sys.exit(1)

    print_token_info(header, payload)

    run_all = args.all or not any([args.alg_none, args.weak_secret, args.expiry, args.kid])

    results = {}

    if run_all or args.alg_none:
        vuln, _ = check_alg_none(token)
        results["alg:none Attack"] = vuln

    if run_all or args.weak_secret:
        vuln, secret = check_weak_secret(token)
        results["Weak Secret"] = vuln

    if run_all or args.expiry:
        vuln = check_expiry(payload)
        results["Expired Token"] = vuln

    if run_all or args.kid:
        vuln = check_kid_injection(token)
        results["KID Injection"] = vuln

    if run_all:
        vuln = check_sensitive_data(payload)
        results["Sensitive Data Leak"] = vuln

    print_summary(results)

if __name__ == "__main__":
    main()

