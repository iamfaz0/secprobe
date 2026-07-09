# 🔒 SecProbe v2.0 - Advanced Penetration Testing Toolkit

A powerful, fast, and comprehensive penetration testing tool designed for **Linux** and **Termux** environments. Built for bug bounty hunters, security researchers, and penetration testers.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)]()

---

## 🎬 Demo Screenshots

### JWT Security Audit
```
╔════════════════════════════════════════════════════════════════════╗
║                    SecProbe v2.0.0                                 ║
╚════════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════════╗
║                         JWT SECURITY AUDIT                         ║
╚════════════════════════════════════════════════════════════════════╝

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type           ┃ Description                             ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ weak_secret    │ JWT signed with weak secret: 'secret'   │
│ CRITICAL │ algorithm_none │ Server accepts 'none' algorithm         │
│ HIGH     │ algorithm_conf │ Potential algorithm confusion attack    │
└──────────┴────────────────┴─────────────────────────────────────────┘
```

### Cloud Security Scan
```
╔════════════════════════════════════════════════════════════════════╗
║                      CLOUD SECURITY SCAN                           ║
╚════════════════════════════════════════════════════════════════════╝

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type            ┃ Description                             ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ s3_bucket_list  │ S3 bucket 'target-backup' is public     │
│ CRITICAL │ s3_bucket_list  │ S3 bucket 'target-assets' is listable   │
│ HIGH     │ azure_blob_pub  │ Azure Blob Storage is publicly acc      │
└──────────┴─────────────────┴─────────────────────────────────────────┘
```

---

## ⚡ Features

### 🔐 JWT Security Auditor
- **Decode** and analyze JWT tokens
- **Brute force** weak secrets with wordlists
- **Algorithm confusion** attacks (RS256 → HS256)
- **"none" algorithm** testing
- **Expiration bypass** checks
- **Sensitive data** detection in claims

### 🌐 API Security Tester
- **Endpoint discovery** from OpenAPI/Swagger specs
- **CORS misconfiguration** detection
- **Rate limiting** tests
- **BOLA/IDOR** vulnerability scanning
- **GraphQL introspection** checks
- **Mass assignment** testing

### 🔍 Reconnaissance Module
- **Port scanning** (async, multi-threaded)
- **Subdomain enumeration** via DNS
- **Technology fingerprinting** (50+ signatures)
- **Directory discovery**
- **SSL/TLS configuration** analysis
- **Sensitive file** exposure detection

### ☁️ Cloud Security Scanner **(NEW in v2.0)**
- **AWS S3 bucket** enumeration & misconfiguration detection
- **Azure Blob Storage** exposure testing
- **GCP Cloud Storage** security checks
- **Public bucket** discovery
- **Writable bucket** detection
- **CloudFront/CDN** configuration testing

### 🔧 Web Fuzzer **(NEW in v2.0)**
- **Path discovery** with extensive wordlist
- **Parameter fuzzing** for vulnerabilities
- **XSS detection** (reflected XSS)
- **SQL Injection** testing (error-based & blind)
- **Command Injection** detection
- **Path Traversal** checks
- **Template Injection** (SSTI) testing
- **NoSQL Injection** detection

### 📊 Report Generator
- **JSON reports** for automation
- **HTML reports** for presentations
- **Markdown** for documentation

---

## 📦 Installation

### Quick Install (Linux/Termux)

```bash
git clone https://github.com/iamfaz0/secprobe.git
cd secprobe
bash install.sh
```

### Manual Install

```bash
# Clone repository
git clone https://github.com/iamfaz0/secprobe.git
cd secprobe

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x secprobe.py

# Run
python3 secprobe.py --help
```

### Termux Specific

```bash
# Update packages
pkg update && pkg upgrade

# Install Python
pkg install python git

# Clone and install
git clone https://github.com/iamfaz0/secprobe.git
cd secprobe
pip install -r requirements.txt
```

---

## 🚀 Usage

### JWT Security Audit

```bash
# Analyze JWT token
secprobe jwt --target "eyJhbGciOiJIUzI1NiJ9..."

# Test with wordlist
secprobe jwt --target "eyJ..." --wordlist secrets.txt --exploit

# Test algorithm confusion
secprobe jwt --target "eyJ..." --alg-none
```

### API Security Testing

```bash
# Basic API scan
secprobe api --target https://api.example.com

# With authentication
secprobe api --target https://api.example.com --auth "Bearer token123"

# With OpenAPI spec
secprobe api --target https://api.example.com --openapi https://api.example.com/swagger.json

# GraphQL testing
secprobe api --target https://api.example.com --graphql
```

### Reconnaissance

```bash
# Basic recon
secprobe recon --target example.com

# Custom ports
secprobe recon --target example.com --ports 80,443,8080,8443

# Full recon with subdomains
secprobe recon --target example.com --subdomains --tech-detect
```

### Cloud Security Scan **(NEW)**

```bash
# Scan for cloud misconfigurations
secprobe cloud --target example.com

# Test specific bucket name pattern
secprobe cloud --target companyname --threads 50
```

### Web Fuzzer **(NEW)**

```bash
# Full web fuzzing
secprobe fuzz --target https://example.com

# Fast scan with more threads
secprobe fuzz --target https://example.com --threads 50
```

### Full Assessment

```bash
# Comprehensive scan
secprobe full --target example.com --ports 80,443,8080

# Save report
secprobe full --target example.com -o report.json

# Generate HTML report
python3 -c "from modules.report_generator import ReportGenerator; \
    import json; r = ReportGenerator(); \
    data = json.load(open('report.json')); \
    open('report.html','w').write(r.generate_html(data['results']))"
```

---

## 📊 Output Examples

### JWT Audit Output
```
╔════════════════════════════════════════════════════════════════════╗
║                    JWT SECURITY AUDIT                              ║
╚════════════════════════════════════════════════════════════════════╝

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type           ┃ Description                          ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ weak_secret    │ JWT signed with weak secret:         │
│          │                │ 'your-256-bit-secret'                │
│ CRITICAL │ algorithm_none │ Server accepts 'none' algorithm    │
│          │                │ - signature bypass possible          │
│ LOW      │ token_lifetime │ No expiration (exp) claim set        │
└──────────┴────────────────┴──────────────────────────────────────┘
```

### Cloud Scan Output
```
╔════════════════════════════════════════════════════════════════════╗
║                    CLOUD SECURITY SCAN                             ║
╚════════════════════════════════════════════════════════════════════╝

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type              ┃ Description                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ s3_bucket_listable│ S3 bucket 'backup' is publicly     │
│          │                   │ listable - 47 files exposed        │
│ CRITICAL │ gcp_bucket_listable│ GCP bucket 'data' is publicly    │
│          │                   │ listable                           │
│ HIGH     │ azure_blob_public │ Azure Storage account accessible   │
└──────────┴───────────────────┴────────────────────────────────────┘
```

### Web Fuzzer Output
```
╔════════════════════════════════════════════════════════════════════╗
║                      WEB FUZZER                                    ║
╚════════════════════════════════════════════════════════════════════╝

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type           ┃ Description                           ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ sensitive_file │ Sensitive file exposed: .env          │
│ HIGH     │ sql_injection  │ SQL error in response for param 'id' │
│ MEDIUM   │ reflected_xss  │ Reflected XSS in parameter 'search'  │
│ HIGH     │ command_inject │ Time-based command injection in        │
│          │ ion            │ param 'cmd' (5.2s response time)     │
└──────────┴────────────────┴─────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
secprobe/
├── secprobe.py              # Main CLI (250+ lines)
├── modules/
│   ├── __init__.py
│   ├── jwt_auditor.py       # JWT testing (1,066 lines)
│   ├── api_tester.py        # API security (1,499 lines)
│   ├── recon.py             # Reconnaissance (1,347 lines)
│   ├── cloud_scanner.py     # Cloud security (1,411 lines) **NEW**
│   ├── web_fuzzer.py        # Web fuzzing (1,491 lines) **NEW**
│   └── report_generator.py  # Reports (948 lines)
├── install.sh               # One-line installer
├── requirements.txt         # Dependencies
├── demo.sh                  # Demo script
└── README.md                # Documentation
```

**Total:** ~8,000+ lines of production-ready code

---

## 💰 Bug Bounty Ready

SecProbe is designed specifically for bug bounty hunting:

### ✅ Tested Vulnerabilities

| Category | Vulnerability | Severity |
|----------|--------------|----------|
| **JWT** | Weak Secret | CRITICAL |
| **JWT** | Algorithm Confusion | CRITICAL |
| **JWT** | Algorithm None | CRITICAL |
| **API** | CORS Misconfiguration | HIGH |
| **API** | BOLA/IDOR | CRITICAL |
| **API** | Mass Assignment | CRITICAL |
| **Cloud** | S3 Bucket Public | CRITICAL |
| **Cloud** | Azure Blob Public | CRITICAL |
| **Cloud** | GCP Bucket Public | CRITICAL |
| **Web** | SQL Injection | HIGH |
| **Web** | XSS | MEDIUM |
| **Web** | Command Injection | HIGH |
| **Web** | Path Traversal | HIGH |

### 🎯 Bug Bounty Platforms Supported
- HackerOne
- Bugcrowd
- Intigriti
- YesWeHack
- Synack
- Open Bug Bounty

---

## 🛠️ Development

### Adding New Modules

1. Create module file in `modules/`
2. Implement the main class with `async def scan()` method
3. Add command-line arguments in `secprobe.py`
4. Register in the main SecProbe class

### Running Tests

```bash
# Test JWT module
python3 -m modules.jwt_auditor

# Test with sample vulnerable targets
python3 secprobe.py jwt --target "TOKEN"
```

---

## 🎯 Use Cases

### Bug Bounty Hunting
- Test JWT implementations for weak secrets
- Find IDOR vulnerabilities in APIs
- Discover exposed admin panels
- Check for CORS misconfigurations
- Find public S3 buckets
- Discover SQL injection vulnerabilities

### Penetration Testing
- Quick reconnaissance during assessments
- API security validation
- Cloud configuration review
- SSL/TLS configuration review
- Technology stack identification

### Security Research
- Test your own applications
- Learn about common vulnerabilities
- Build custom security checks

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only.**

- Only use on systems you own or have explicit permission to test
- Respect bug bounty program rules and scopes
- The authors are not responsible for misuse or damage caused by this tool

**By using SecProbe, you agree to:**
- Follow responsible disclosure practices
- Not use this tool for illegal activities
- Accept full responsibility for your actions

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Feature Requests
- More cloud providers (DigitalOcean, Linode, etc.)
- Docker/container security scanning
- Kubernetes security checks
- Additional web vulnerability tests

---

## 📜 License

MIT License - see LICENSE file for details

---

## 🔗 Connect

- **Author:** iamfaz0
- **GitHub:** https://github.com/iamfaz0/secprobe
- **Issues:** https://github.com/iamfaz0/secprobe/issues

---

## 💡 Tips

### Termux Optimization

```bash
# Prevent pip from installing into system packages
export PIP_NO_CACHE_DIR=1

# Install in user space
pip install --user -r requirements.txt
```

### Wordlists

SecProbe comes with built-in common secrets, but you can use custom wordlists:

```bash
# SecLists wordlists (recommended)
https://github.com/danielmiessler/SecLists

# Use with SecProbe
secprobe jwt --target TOKEN --wordlist /path/to/wordlist.txt
```

### Performance Tips

```bash
# Increase threads for faster scanning
secprobe recon --target example.com --threads 100

# Use --quiet for CI/CD pipelines
secprobe full --target example.com --quiet -o report.json
```

---

## 🆕 What's New in v2.0

### New Modules
- **Cloud Security Scanner** - AWS, Azure, GCP bucket testing
- **Web Fuzzer** - XSS, SQLi, Command Injection, Path Traversal testing

### Enhanced Features
- 2x more vulnerability checks
- Better async performance
- Improved reporting
- More payload types

---

**Happy Hunting! 🐛🔍**

If this tool helps you find a bug, consider giving it a ⭐ on GitHub!