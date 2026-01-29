# SecurePass - Intelligent Password Security Analyzer

🔐 A comprehensive password security analysis tool that helps users understand password strength, detect weaknesses, and learn how attackers exploit poor passwords.

## Features

### Core Features
- **Password Strength Analysis**: Length, complexity, character variety analysis
- **Entropy Calculation**: Mathematical measurement of password randomness
- **Time-to-Crack Estimation**: Realistic estimates based on modern hardware
- **Character Type Detection**: Lowercase, uppercase, digits, special characters

### Security Checks
- **Dictionary Attack Detection**: Check against common password lists
- **Pattern Recognition**: Detect keyboard patterns, sequences, repeated characters
- **Common Password Check**: Test against known leaked password databases
- **Leet Speak Detection**: Identify common character substitutions

### Hash Demonstrations
- **MD5**: Fast but broken (educational purposes)
- **SHA-256**: Secure for general hashing
- **bcrypt**: Recommended for password storage

### Policy Enforcement
- **Multiple Policy Levels**: Basic, Standard, Strong, Enterprise
- **Customizable Rules**: Minimum length, character requirements, etc.
- **Compliance Checking**: Validate passwords against organizational policies

### Educational Cracking Demo
- **Dictionary Attack Simulation**: Demonstrates weakness of common passwords
- **Brute Force Demonstration**: Shows exponential time complexity
- **Rule-Based Attack**: Common password mutations

### Reporting
- **Multiple Formats**: Text, JSON, HTML
- **Comprehensive Analysis**: All findings in one report
- **Export Capability**: Save reports for documentation

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone or download the project
cd SecurePass

# Install dependencies
pip install -r requirements.txt
```

### Optional: RockYou Wordlist
For enhanced dictionary checking, download the RockYou wordlist:
```bash
# The wordlist can be found in security research repositories
# Place it in the project directory and reference with --wordlist flag
```

## Usage

### Command Line Interface (CLI)

```bash
# Interactive mode (recommended for first-time users)
python main.py --interactive

# Quick password analysis
python main.py --analyze -p "YourPassword123"

# Check against dictionary
python main.py --check-dictionary

# View hash demonstrations
python main.py --hash

# Validate against policy
python main.py --policy strong

# Generate security report
python main.py --report -o report.html --format html

# Educational cracking demo
python main.py --crack-demo
```

### Graphical User Interface (GUI)

```bash
# Launch the GUI
python main.py --gui
```

### Python API

```python
from securepass.analyzer import PasswordAnalyzer, quick_analyze
from securepass.dictionary_checker import DictionaryChecker
from securepass.hasher import PasswordHasher, hash_password
from securepass.policy import PasswordPolicy, PolicyLevel
from securepass.report import generate_security_report

# Quick analysis
result = quick_analyze("MyPassword123")
print(f"Strength: {result['strength_label']} ({result['strength_score']}/100)")

# Detailed analysis
analyzer = PasswordAnalyzer()
analysis = analyzer.analyze("MyPassword123")
print(f"Entropy: {analysis.entropy:.2f} bits")
print(f"Time to crack: {analysis.time_to_crack}")

# Dictionary check
checker = DictionaryChecker()
result = checker.full_check("password123")
print(f"Is common password: {result['is_common_password']}")

# Hash a password
hash_result = hash_password("MyPassword123", "bcrypt")
print(f"Hash: {hash_result.hash_value}")

# Policy validation
policy = PasswordPolicy(PolicyLevel.STRONG)
result = policy.validate("MyPassword123!")
print(f"Passed: {result.passed}")

# Generate report
report = generate_security_report("MyPassword123", format="text")
print(report)
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-i, --interactive` | Run in interactive mode |
| `-a, --analyze` | Analyze password strength |
| `-d, --check-dictionary` | Check against dictionary |
| `-H, --hash` | Show hash demonstrations |
| `--policy LEVEL` | Validate against policy (basic/standard/strong/enterprise) |
| `-r, --report` | Generate security report |
| `--crack-demo` | Educational cracking demonstration |
| `-p, --password` | Password to analyze |
| `-u, --username` | Username for policy validation |
| `-o, --output` | Output file path |
| `-f, --format` | Output format (text/json/html) |
| `-w, --wordlist` | Path to wordlist file |
| `--no-color` | Disable colored output |

## Policy Levels

| Level | Min Length | Uppercase | Lowercase | Digits | Special | Notes |
|-------|------------|-----------|-----------|--------|---------|-------|
| Basic | 6 | No | Yes | No | No | Minimal security |
| Standard | 8 | Yes | Yes | Yes | No | Recommended minimum |
| Strong | 12 | Yes | Yes | Yes | Yes | Good security |
| Enterprise | 16 | Yes | Yes | Yes | Yes | Maximum security + entropy check |

## Security Recommendations

### Password Best Practices
1. **Use 12+ characters** - Longer is always better
2. **Mix character types** - Upper, lower, numbers, symbols
3. **Avoid patterns** - No keyboard sequences, dates, or dictionary words
4. **Use unique passwords** - Never reuse passwords across sites
5. **Consider passphrases** - "correct horse battery staple" style
6. **Use a password manager** - Generate and store complex passwords

### What NOT to Do
- ❌ Use common passwords (password123, qwerty, etc.)
- ❌ Use personal information (birthdays, names, etc.)
- ❌ Use simple substitutions (p@ssw0rd)
- ❌ Reuse passwords across accounts
- ❌ Share passwords with others

## Project Structure

```
SecurePass/
├── main.py                    # Main entry point
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── securepass/
    ├── __init__.py           # Package initialization
    ├── analyzer.py           # Password strength analyzer
    ├── dictionary_checker.py # Dictionary/common password checks
    ├── hasher.py             # Hash demonstrations
    ├── cracker.py            # Educational cracking demo
    ├── policy.py             # Policy enforcement
    ├── report.py             # Report generation
    ├── cli.py                # Command-line interface
    └── gui.py                # Graphical interface (Tkinter)
```

## Educational Purpose

⚠️ **IMPORTANT**: The password cracking demonstration feature is for **educational purposes only**. It is designed to:

1. Help users understand why weak passwords are vulnerable
2. Demonstrate the importance of password complexity
3. Show how quickly common passwords can be cracked

**Never use these techniques against systems you don't own or have explicit permission to test.**

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is for educational purposes. Use responsibly.

## Acknowledgments

- [bcrypt](https://pypi.org/project/bcrypt/) - Secure password hashing
- [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) - Password strength estimation
- Security researchers who maintain password lists for educational purposes

---

**Stay Secure! 🔐**
