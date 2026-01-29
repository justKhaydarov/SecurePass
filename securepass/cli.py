#!/usr/bin/env python3
"""
SecurePass CLI - Command Line Interface
Intelligent Password Security Analyzer
"""

import argparse
import sys
import getpass
from typing import Optional

from securepass.analyzer import PasswordAnalyzer
from securepass.dictionary_checker import DictionaryChecker
from securepass.hasher import PasswordHasher, BCRYPT_AVAILABLE
from securepass.cracker import PasswordCracker, simulate_crack
from securepass.policy import PasswordPolicy, PolicyLevel
from securepass.report import SecurityReportGenerator, generate_security_report


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Add color to text."""
    return f"{color}{text}{Colors.END}"


def print_banner():
    """Print the SecurePass banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██████╗ ██████╗║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██████╔╝███████║███████╗███████╗║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║     ██║  ██║███████║███████║║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝║
║                                                                       ║
║              Intelligent Password Security Analyzer                   ║
║                         Version 1.0.0                                 ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(colorize(banner, Colors.CYAN))


def get_strength_color(score: int) -> str:
    """Get color based on strength score."""
    if score >= 80:
        return Colors.GREEN
    elif score >= 60:
        return Colors.CYAN
    elif score >= 40:
        return Colors.YELLOW
    else:
        return Colors.RED


def print_analysis_results(password: str, analyzer: PasswordAnalyzer):
    """Print password analysis results."""
    analysis = analyzer.analyze(password)
    color = get_strength_color(analysis.strength_score)
    
    print(f"\n{colorize('═' * 60, Colors.BLUE)}")
    print(colorize("  PASSWORD ANALYSIS RESULTS", Colors.BOLD))
    print(f"{colorize('═' * 60, Colors.BLUE)}\n")
    
    # Basic Info
    print(f"  {colorize('Password Length:', Colors.CYAN)} {analysis.password_length} characters")
    print(f"  {colorize('Character Set Size:', Colors.CYAN)} {analysis.charset_size} possible characters")
    print(f"  {colorize('Entropy:', Colors.CYAN)} {analysis.entropy:.2f} bits")
    
    # Strength Score
    print(f"\n  {colorize('Strength Score:', Colors.CYAN)} {colorize(f'{analysis.strength_score}/100', color)}")
    print(f"  {colorize('Strength Label:', Colors.CYAN)} {colorize(analysis.strength_label, color)}")
    print(f"  {colorize('Time to Crack:', Colors.CYAN)} {analysis.time_to_crack}")
    
    # Character Types
    print(f"\n  {colorize('Character Types:', Colors.CYAN)}")
    print(f"    • Lowercase: {colorize('✓', Colors.GREEN) if analysis.has_lowercase else colorize('✗', Colors.RED)}")
    print(f"    • Uppercase: {colorize('✓', Colors.GREEN) if analysis.has_uppercase else colorize('✗', Colors.RED)}")
    print(f"    • Digits:    {colorize('✓', Colors.GREEN) if analysis.has_digits else colorize('✗', Colors.RED)}")
    print(f"    • Special:   {colorize('✓', Colors.GREEN) if analysis.has_special else colorize('✗', Colors.RED)}")
    
    # Weaknesses
    if analysis.weaknesses:
        print(f"\n  {colorize('⚠ Weaknesses Found:', Colors.YELLOW)}")
        for weakness in analysis.weaknesses:
            print(f"    • {weakness}")
    
    # Recommendations
    if analysis.recommendations:
        print(f"\n  {colorize('💡 Recommendations:', Colors.CYAN)}")
        for rec in analysis.recommendations:
            print(f"    • {rec}")
    
    print(f"\n{colorize('═' * 60, Colors.BLUE)}\n")


def print_dictionary_check(password: str, checker: DictionaryChecker):
    """Print dictionary check results."""
    result = checker.full_check(password)
    
    print(f"\n{colorize('═' * 60, Colors.BLUE)}")
    print(colorize("  DICTIONARY & COMMON PASSWORD CHECK", Colors.BOLD))
    print(f"{colorize('═' * 60, Colors.BLUE)}\n")
    
    risk_colors = {
        'critical': Colors.RED,
        'high': Colors.RED,
        'medium': Colors.YELLOW,
        'low': Colors.GREEN
    }
    risk_color = risk_colors.get(result['risk_level'], Colors.WHITE)
    
    print(f"  {colorize('Risk Level:', Colors.CYAN)} {colorize(result['risk_level'].upper(), risk_color)}")
    
    if result['is_common_password']:
        print(f"\n  {colorize('⚠ CRITICAL:', Colors.RED)} This password is in the common passwords list!")
    else:
        print(f"\n  {colorize('✓', Colors.GREEN)} Not a commonly used password")
    
    if result['contains_dictionary_words']:
        print(f"\n  {colorize('⚠ Warning:', Colors.YELLOW)} Contains dictionary words:")
        for word in result['dictionary_words_found']:
            print(f"    • {word}")
    
    if result['is_variation']:
        print(f"\n  {colorize('⚠ Warning:', Colors.YELLOW)} Appears to be a variation of common passwords:")
        for var in result['variations_found']:
            print(f"    • {var}")
    
    print(f"\n{colorize('═' * 60, Colors.BLUE)}\n")


def print_hash_demo(password: str, hasher: PasswordHasher):
    """Print hash demonstration."""
    print(f"\n{colorize('═' * 60, Colors.BLUE)}")
    print(colorize("  HASH DEMONSTRATION", Colors.BOLD))
    print(f"{colorize('═' * 60, Colors.BLUE)}\n")
    
    results = hasher.hash_all(password)
    
    for algo, result in results.items():
        secure_status = colorize('✓ Secure', Colors.GREEN) if result.is_secure else colorize('✗ Not Secure', Colors.RED)
        
        print(f"  {colorize(result.algorithm, Colors.CYAN)}:")
        print(f"    Hash: {result.hash_value[:50]}...")
        if result.salt:
            print(f"    Salt: {result.salt[:20]}...")
        print(f"    Time: {result.time_taken * 1000:.4f} ms")
        print(f"    Status: {secure_status}")
        print(f"    Note: {result.notes}")
        print()
    
    print(f"  {colorize('💡 Tip:', Colors.YELLOW)} Always use bcrypt for password storage!")
    print(f"\n{colorize('═' * 60, Colors.BLUE)}\n")


def print_policy_check(password: str, level: PolicyLevel, username: Optional[str] = None):
    """Print policy validation results."""
    policy = PasswordPolicy(level)
    result = policy.validate(password, username)
    
    print(f"\n{colorize('═' * 60, Colors.BLUE)}")
    print(colorize(f"  POLICY VALIDATION ({level.value.upper()})", Colors.BOLD))
    print(f"{colorize('═' * 60, Colors.BLUE)}\n")
    
    status_color = Colors.GREEN if result.passed else Colors.RED
    status_text = "PASSED ✓" if result.passed else "FAILED ✗"
    
    print(f"  {colorize('Status:', Colors.CYAN)} {colorize(status_text, status_color)}")
    print(f"  {colorize('Score:', Colors.CYAN)} {result.score}/100")
    
    print(f"\n  {colorize('Policy Requirements:', Colors.CYAN)}")
    print(policy.get_requirements_text())
    
    if result.passed_rules:
        print(f"\n  {colorize('✓ Passed Rules:', Colors.GREEN)}")
        for rule in result.passed_rules:
            print(f"    • {rule}")
    
    if result.failed_rules:
        print(f"\n  {colorize('✗ Failed Rules:', Colors.RED)}")
        for rule in result.failed_rules:
            print(f"    • {rule}")
    
    print(f"\n{colorize('═' * 60, Colors.BLUE)}\n")


def run_interactive_mode():
    """Run interactive mode."""
    print_banner()
    
    print(colorize("\nWelcome to SecurePass Interactive Mode!", Colors.GREEN))
    print("Analyze passwords securely - your input is hidden.\n")
    
    while True:
        print(colorize("Options:", Colors.CYAN))
        print("  1. Analyze Password")
        print("  2. Check Against Dictionary")
        print("  3. View Hash Demonstrations")
        print("  4. Validate Against Policy")
        print("  5. Generate Full Report")
        print("  6. Crack Demo (Educational)")
        print("  7. Exit")
        
        choice = input(colorize("\nSelect option [1-7]: ", Colors.YELLOW)).strip()
        
        if choice == '7':
            print(colorize("\nThank you for using SecurePass! Stay secure! 🔐\n", Colors.GREEN))
            break
        
        if choice in ['1', '2', '3', '4', '5', '6']:
            password = getpass.getpass(colorize("Enter password to analyze: ", Colors.CYAN))
            
            if not password:
                print(colorize("No password entered. Please try again.\n", Colors.RED))
                continue
            
            if choice == '1':
                analyzer = PasswordAnalyzer()
                print_analysis_results(password, analyzer)
            
            elif choice == '2':
                checker = DictionaryChecker()
                print_dictionary_check(password, checker)
            
            elif choice == '3':
                hasher = PasswordHasher()
                print_hash_demo(password, hasher)
            
            elif choice == '4':
                print("\nSelect policy level:")
                print("  1. Basic")
                print("  2. Standard")
                print("  3. Strong")
                print("  4. Enterprise")
                
                level_choice = input(colorize("Select [1-4]: ", Colors.YELLOW)).strip()
                levels = {
                    '1': PolicyLevel.BASIC,
                    '2': PolicyLevel.STANDARD,
                    '3': PolicyLevel.STRONG,
                    '4': PolicyLevel.ENTERPRISE
                }
                level = levels.get(level_choice, PolicyLevel.STANDARD)
                print_policy_check(password, level)
            
            elif choice == '5':
                output_format = input(colorize("Output format (text/json/html) [text]: ", Colors.CYAN)).strip() or 'text'
                save_path = input(colorize("Save to file (leave empty for stdout): ", Colors.CYAN)).strip()
                
                report = generate_security_report(
                    password,
                    output_path=save_path if save_path else None,
                    format=output_format,
                    include_hashes=True
                )
                
                if not save_path:
                    print(report)
                else:
                    print(colorize(f"\nReport saved to: {save_path}", Colors.GREEN))
            
            elif choice == '6':
                print(colorize("\n⚠️  EDUCATIONAL DEMONSTRATION ONLY ⚠️", Colors.YELLOW))
                print("This shows how weak passwords can be cracked.\n")
                
                hash_type = input(colorize("Hash type (md5/sha256/bcrypt) [md5]: ", Colors.CYAN)).strip() or 'md5'
                result = simulate_crack(password, hash_type)
                print(result)
        
        else:
            print(colorize("Invalid option. Please select 1-7.\n", Colors.RED))


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='SecurePass - Intelligent Password Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  securepass --interactive                     Interactive mode
  securepass --analyze                         Analyze password (prompted)
  securepass --analyze -p "MyPassword123"      Analyze specific password
  securepass --check-dictionary                Check against common passwords
  securepass --hash                            Show hash demonstrations
  securepass --policy standard                 Validate against policy
  securepass --report -o report.html --format html  Generate HTML report
  securepass --crack-demo                      Educational cracking demo
        '''
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-i', '--interactive', action='store_true',
                           help='Run in interactive mode')
    mode_group.add_argument('-a', '--analyze', action='store_true',
                           help='Analyze password strength')
    mode_group.add_argument('-d', '--check-dictionary', action='store_true',
                           help='Check against dictionary/common passwords')
    mode_group.add_argument('-H', '--hash', action='store_true',
                           help='Show hash demonstrations')
    mode_group.add_argument('--policy', choices=['basic', 'standard', 'strong', 'enterprise'],
                           help='Validate against specified policy level')
    mode_group.add_argument('-r', '--report', action='store_true',
                           help='Generate security report')
    mode_group.add_argument('--crack-demo', action='store_true',
                           help='Educational password cracking demonstration')
    
    # Options
    parser.add_argument('-p', '--password', type=str,
                       help='Password to analyze (will prompt if not provided)')
    parser.add_argument('-u', '--username', type=str,
                       help='Username for policy validation')
    parser.add_argument('-o', '--output', type=str,
                       help='Output file path for reports')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'html'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('-w', '--wordlist', type=str,
                       help='Path to wordlist file (e.g., rockyou.txt)')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    parser.add_argument('-v', '--version', action='version',
                       version='SecurePass 1.0.0')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')
    
    # Default to interactive mode if no arguments
    if len(sys.argv) == 1 or args.interactive:
        run_interactive_mode()
        return
    
    # Get password
    password = args.password
    if not password:
        password = getpass.getpass("Enter password: ")
    
    if not password:
        print(colorize("Error: No password provided.", Colors.RED))
        sys.exit(1)
    
    # Execute selected mode
    if args.analyze:
        analyzer = PasswordAnalyzer()
        print_analysis_results(password, analyzer)
    
    elif args.check_dictionary:
        checker = DictionaryChecker(args.wordlist)
        print_dictionary_check(password, checker)
    
    elif args.hash:
        hasher = PasswordHasher()
        print_hash_demo(password, hasher)
    
    elif args.policy:
        levels = {
            'basic': PolicyLevel.BASIC,
            'standard': PolicyLevel.STANDARD,
            'strong': PolicyLevel.STRONG,
            'enterprise': PolicyLevel.ENTERPRISE
        }
        print_policy_check(password, levels[args.policy], args.username)
    
    elif args.report:
        report = generate_security_report(
            password,
            output_path=args.output,
            format=args.format,
            include_hashes=True
        )
        
        if not args.output:
            print(report)
        else:
            print(colorize(f"Report saved to: {args.output}", Colors.GREEN))
    
    elif args.crack_demo:
        print(colorize("\n⚠️  EDUCATIONAL DEMONSTRATION ONLY ⚠️\n", Colors.YELLOW))
        result = simulate_crack(password, 'md5')
        print(result)


if __name__ == '__main__':
    main()
