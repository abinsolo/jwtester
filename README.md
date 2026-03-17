# JWTester 🔐
> JWT Vulnerability Scanner for Bug Bounty & Penetration Testing

Built by **Abin A** — scans JWT tokens for the most critical 
vulnerabilities found in real-world bug bounty programs.

## What It Tests
| # | Test | Description |
|---|------|-------------|
| 1 | alg:none Attack | Removes signature verification requirement |
| 2 | Weak Secret Brute Force | Tests 20+ common secrets against HMAC tokens |
| 3 | Expiry Check | Detects expired or missing expiry claims |
| 4 | KID Injection | Flags KID header for SQL/path injection testing |
| 5 | Sensitive Data Leak | Detects passwords/keys exposed in payload |

## Installation
```bash
git clone https://github.com/abinsolo/jwtester
cd jwtester
pip3 install -r requirements.txt
```

## Usage
```bash
# Run all tests
python3 jwt_tester.py -t <your_jwt_token>

# Run specific test
python3 jwt_tester.py -t <token> --alg-none
python3 jwt_tester.py -t <token> --weak-secret
python3 jwt_tester.py -t <token> --expiry
python3 jwt_tester.py -t <token> --kid
```

## Generate a Test Token
```bash
python3 -c "import jwt; print(jwt.encode(
  {'user':'admin','role':'superuser'}, 
  'secret', algorithm='HS256'))"
```

## Example Output
```
[HEADER] alg      HS256
[HEADER] typ      JWT
[PAYLOAD] user    admin
[PAYLOAD] role    superuser

[!] VULNERABLE — Weak secret found: 'secret'
[!] VULNERABLE — alg:none token generated
[+] No KID claim found
[+] No sensitive data in payload

╭─────── JWTester Results ───────╮
│ VULNERABILITIES FOUND          │
│ [!] Weak Secret                │
│ [!] alg:none Attack            │
│ [+] Expired Token — OK         │
│ [+] KID Injection — OK         │
╰────────────────────────────────╯
```

## Legal
Only test tokens you own or have explicit permission to test.

## Author
**Abin A** — Bug Bounty Researcher | Penetration Tester  
LinkedIn: linkedin.com/in/abin-a-937196382  
GitHub: github.com/abinsolo  
TryHackMe: tryhackme.com/p/Abinsolo
