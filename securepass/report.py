"""
Security Report Generation Module
Exports password analysis results as security reports.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from .analyzer import PasswordAnalyzer, PasswordAnalysis
from .dictionary_checker import DictionaryChecker
from .hasher import PasswordHasher
from .policy import PasswordPolicy, PolicyLevel


class SecurityReportGenerator:
    """Generates comprehensive security reports for password analysis."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.analyzer = PasswordAnalyzer()
        self.dictionary_checker = DictionaryChecker()
        self.hasher = PasswordHasher()
    
    def generate_report(self, password: str, 
                       policy_level: PolicyLevel = PolicyLevel.STANDARD,
                       include_hashes: bool = False,
                       username: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        
        Args:
            password: Password to analyze
            policy_level: Policy level to validate against
            include_hashes: Whether to include hash demonstrations
            username: Optional username for policy check
            
        Returns:
            Dictionary containing the full report
        """
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'SecurePass - Intelligent Password Security Analyzer',
                'version': '1.0.0'
            },
            'password_info': {
                'length': len(password),
                'masked': '*' * len(password)
            },
            'analysis': {},
            'dictionary_check': {},
            'policy_validation': {},
            'recommendations': [],
            'overall_assessment': {}
        }
        
        # Password Analysis
        analysis = self.analyzer.analyze(password)
        report['analysis'] = {
            'length': analysis.password_length,
            'character_types': {
                'has_lowercase': analysis.has_lowercase,
                'has_uppercase': analysis.has_uppercase,
                'has_digits': analysis.has_digits,
                'has_special': analysis.has_special,
                'has_whitespace': analysis.has_whitespace
            },
            'charset_size': analysis.charset_size,
            'entropy_bits': round(analysis.entropy, 2),
            'strength_score': analysis.strength_score,
            'strength_label': analysis.strength_label,
            'estimated_crack_time': analysis.time_to_crack,
            'weaknesses': analysis.weaknesses,
            'pattern_warnings': analysis.pattern_warnings
        }
        
        # Dictionary Check
        dict_result = self.dictionary_checker.full_check(password)
        report['dictionary_check'] = {
            'is_common_password': dict_result['is_common_password'],
            'contains_dictionary_words': dict_result['contains_dictionary_words'],
            'dictionary_words_found': dict_result['dictionary_words_found'],
            'is_variation': dict_result['is_variation'],
            'variations_found': dict_result['variations_found'],
            'risk_level': dict_result['risk_level'],
            'warnings': dict_result['warnings']
        }
        
        # Policy Validation
        policy = PasswordPolicy(policy_level)
        policy_result = policy.validate(password, username)
        report['policy_validation'] = {
            'policy_level': policy_level.value,
            'passed': policy_result.passed,
            'score': policy_result.score,
            'passed_rules': policy_result.passed_rules,
            'failed_rules': policy_result.failed_rules,
            'warnings': policy_result.warnings,
            'requirements': policy.get_requirements_text()
        }
        
        # Hash Demonstrations (optional)
        if include_hashes:
            hashes = self.hasher.hash_all(password)
            report['hash_demonstrations'] = {}
            for algo, result in hashes.items():
                report['hash_demonstrations'][algo] = {
                    'algorithm': result.algorithm,
                    'hash_value': result.hash_value,
                    'salt': result.salt,
                    'time_ms': round(result.time_taken * 1000, 4),
                    'is_secure': result.is_secure,
                    'notes': result.notes
                }
        
        # Compile Recommendations
        all_recommendations = set()
        all_recommendations.update(analysis.recommendations)
        all_recommendations.update(policy_result.recommendations)
        
        if dict_result['is_common_password']:
            all_recommendations.add("CRITICAL: Change this password immediately - it's in common password lists!")
        
        if dict_result['is_variation']:
            all_recommendations.add("Avoid using variations of common passwords")
        
        report['recommendations'] = list(all_recommendations)
        
        # Overall Assessment
        overall_score = self._calculate_overall_score(
            analysis.strength_score,
            policy_result.score,
            dict_result['risk_level']
        )
        
        report['overall_assessment'] = {
            'score': overall_score,
            'rating': self._get_rating(overall_score),
            'summary': self._generate_summary(overall_score, analysis, dict_result, policy_result)
        }
        
        return report
    
    def _calculate_overall_score(self, strength_score: int, 
                                 policy_score: int, 
                                 dict_risk: str) -> int:
        """Calculate overall security score."""
        # Base score from strength and policy
        base_score = (strength_score * 0.5) + (policy_score * 0.5)
        
        # Apply dictionary risk penalty
        risk_penalties = {
            'critical': 50,
            'high': 30,
            'medium': 15,
            'low': 0
        }
        penalty = risk_penalties.get(dict_risk, 0)
        
        return max(0, int(base_score - penalty))
    
    def _get_rating(self, score: int) -> str:
        """Get rating label from score."""
        if score >= 80:
            return "Excellent"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        elif score >= 20:
            return "Poor"
        else:
            return "Critical"
    
    def _generate_summary(self, score: int, analysis: PasswordAnalysis,
                         dict_result: dict, policy_result) -> str:
        """Generate a human-readable summary."""
        if score >= 80:
            return "This password demonstrates strong security characteristics. Continue using unique passwords and consider a password manager."
        elif score >= 60:
            return "This password has good security but could be improved. Consider adding more character variety or length."
        elif score >= 40:
            return "This password has moderate security issues. It's recommended to create a stronger password with more complexity."
        elif score >= 20:
            return "This password has significant security weaknesses. It should be changed to a stronger alternative."
        else:
            return "CRITICAL: This password is extremely weak and should be changed immediately. Use a password generator for a secure alternative."
    
    def export_text(self, report: Dict[str, Any]) -> str:
        """Export report as formatted text."""
        lines = []
        lines.append("=" * 70)
        lines.append("SECUREPASS SECURITY REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {report['report_metadata']['generated_at']}")
        lines.append("")
        
        # Overall Assessment
        lines.append("-" * 70)
        lines.append("OVERALL ASSESSMENT")
        lines.append("-" * 70)
        overall = report['overall_assessment']
        lines.append(f"Score: {overall['score']}/100 ({overall['rating']})")
        lines.append(f"Summary: {overall['summary']}")
        lines.append("")
        
        # Password Analysis
        lines.append("-" * 70)
        lines.append("PASSWORD ANALYSIS")
        lines.append("-" * 70)
        analysis = report['analysis']
        lines.append(f"Length: {analysis['length']} characters")
        lines.append(f"Entropy: {analysis['entropy_bits']} bits")
        lines.append(f"Strength: {analysis['strength_label']} ({analysis['strength_score']}/100)")
        lines.append(f"Estimated Crack Time: {analysis['estimated_crack_time']}")
        lines.append("")
        
        lines.append("Character Types:")
        char_types = analysis['character_types']
        lines.append(f"  • Lowercase: {'Yes' if char_types['has_lowercase'] else 'No'}")
        lines.append(f"  • Uppercase: {'Yes' if char_types['has_uppercase'] else 'No'}")
        lines.append(f"  • Digits: {'Yes' if char_types['has_digits'] else 'No'}")
        lines.append(f"  • Special: {'Yes' if char_types['has_special'] else 'No'}")
        lines.append("")
        
        if analysis['weaknesses']:
            lines.append("Weaknesses Found:")
            for weakness in analysis['weaknesses']:
                lines.append(f"  ⚠ {weakness}")
            lines.append("")
        
        # Dictionary Check
        lines.append("-" * 70)
        lines.append("DICTIONARY & COMMON PASSWORD CHECK")
        lines.append("-" * 70)
        dict_check = report['dictionary_check']
        lines.append(f"Risk Level: {dict_check['risk_level'].upper()}")
        lines.append(f"Is Common Password: {'Yes ⚠' if dict_check['is_common_password'] else 'No ✓'}")
        lines.append(f"Contains Dictionary Words: {'Yes ⚠' if dict_check['contains_dictionary_words'] else 'No ✓'}")
        
        if dict_check['dictionary_words_found']:
            lines.append(f"  Words Found: {', '.join(dict_check['dictionary_words_found'])}")
        
        if dict_check['warnings']:
            for warning in dict_check['warnings']:
                lines.append(f"  ⚠ {warning}")
        lines.append("")
        
        # Policy Validation
        lines.append("-" * 70)
        lines.append(f"POLICY VALIDATION ({report['policy_validation']['policy_level'].upper()})")
        lines.append("-" * 70)
        policy = report['policy_validation']
        lines.append(f"Status: {'PASSED ✓' if policy['passed'] else 'FAILED ✗'}")
        lines.append(f"Score: {policy['score']}/100")
        lines.append("")
        
        if policy['failed_rules']:
            lines.append("Failed Rules:")
            for rule in policy['failed_rules']:
                lines.append(f"  ✗ {rule}")
            lines.append("")
        
        # Hash Demonstrations
        if 'hash_demonstrations' in report:
            lines.append("-" * 70)
            lines.append("HASH DEMONSTRATIONS")
            lines.append("-" * 70)
            for algo, data in report['hash_demonstrations'].items():
                lines.append(f"\n{data['algorithm']}:")
                lines.append(f"  Hash: {data['hash_value'][:50]}...")
                lines.append(f"  Time: {data['time_ms']} ms")
                lines.append(f"  Secure: {'Yes ✓' if data['is_secure'] else 'No ✗'}")
            lines.append("")
        
        # Recommendations
        lines.append("-" * 70)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 70)
        for rec in report['recommendations']:
            lines.append(f"• {rec}")
        
        lines.append("")
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def export_json(self, report: Dict[str, Any], pretty: bool = True) -> str:
        """Export report as JSON."""
        if pretty:
            return json.dumps(report, indent=2)
        return json.dumps(report)
    
    def export_html(self, report: Dict[str, Any]) -> str:
        """Export report as HTML."""
        overall = report['overall_assessment']
        analysis = report['analysis']
        dict_check = report['dictionary_check']
        policy = report['policy_validation']
        
        # Determine color based on score
        if overall['score'] >= 80:
            score_color = '#28a745'  # Green
        elif overall['score'] >= 60:
            score_color = '#17a2b8'  # Blue
        elif overall['score'] >= 40:
            score_color = '#ffc107'  # Yellow
        else:
            score_color = '#dc3545'  # Red
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePass Security Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .score-box {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, {score_color}, {score_color}dd);
            color: white;
            border-radius: 10px;
            margin: 20px 0;
        }}
        .score-number {{
            font-size: 48px;
            font-weight: bold;
        }}
        .score-label {{
            font-size: 24px;
            opacity: 0.9;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }}
        .warning {{
            color: #856404;
            background: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }}
        .success {{
            color: #155724;
            background: #d4edda;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }}
        .danger {{
            color: #721c24;
            background: #f8d7da;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }}
        ul {{
            padding-left: 20px;
        }}
        li {{
            margin: 5px 0;
        }}
        .timestamp {{
            color: #666;
            font-size: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SecurePass Security Report</h1>
        <p class="timestamp">Generated: {report['report_metadata']['generated_at']}</p>
        
        <div class="score-box">
            <div class="score-number">{overall['score']}/100</div>
            <div class="score-label">{overall['rating']}</div>
        </div>
        
        <div class="section">
            <p><strong>Summary:</strong> {overall['summary']}</p>
        </div>
        
        <h2>📊 Password Analysis</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Length</td><td>{analysis['length']} characters</td></tr>
            <tr><td>Entropy</td><td>{analysis['entropy_bits']} bits</td></tr>
            <tr><td>Strength</td><td>{analysis['strength_label']} ({analysis['strength_score']}/100)</td></tr>
            <tr><td>Crack Time</td><td>{analysis['estimated_crack_time']}</td></tr>
        </table>
        
        <h3>Character Types</h3>
        <ul>
            <li>Lowercase: {'✓' if analysis['character_types']['has_lowercase'] else '✗'}</li>
            <li>Uppercase: {'✓' if analysis['character_types']['has_uppercase'] else '✗'}</li>
            <li>Digits: {'✓' if analysis['character_types']['has_digits'] else '✗'}</li>
            <li>Special: {'✓' if analysis['character_types']['has_special'] else '✗'}</li>
        </ul>
        
        {''.join([f'<div class="warning">⚠ {w}</div>' for w in analysis['weaknesses']]) if analysis['weaknesses'] else '<div class="success">✓ No significant weaknesses detected</div>'}
        
        <h2>📚 Dictionary Check</h2>
        <div class="{'danger' if dict_check['risk_level'] in ['critical', 'high'] else 'warning' if dict_check['risk_level'] == 'medium' else 'success'}">
            Risk Level: <strong>{dict_check['risk_level'].upper()}</strong>
        </div>
        
        {'<div class="danger">⚠ This is a commonly used password!</div>' if dict_check['is_common_password'] else ''}
        {'<div class="warning">⚠ Contains dictionary words: ' + ', '.join(dict_check['dictionary_words_found']) + '</div>' if dict_check['contains_dictionary_words'] else ''}
        
        <h2>📋 Policy Validation ({policy['policy_level'].upper()})</h2>
        <div class="{'success' if policy['passed'] else 'danger'}">
            Status: <strong>{'PASSED ✓' if policy['passed'] else 'FAILED ✗'}</strong> (Score: {policy['score']}/100)
        </div>
        
        {('<h3>Failed Rules</h3><ul>' + ''.join([f'<li class="danger">{r}</li>' for r in policy['failed_rules']]) + '</ul>') if policy['failed_rules'] else ''}
        
        <h2>💡 Recommendations</h2>
        <ul>
            {''.join([f'<li>{r}</li>' for r in report['recommendations']])}
        </ul>
        
        <hr>
        <p style="text-align: center; color: #666; font-size: 12px;">
            Generated by SecurePass - Intelligent Password Security Analyzer v1.0.0
        </p>
    </div>
</body>
</html>'''
        
        return html
    
    def save_report(self, report: Dict[str, Any], 
                   filepath: str, 
                   format: str = 'text') -> str:
        """
        Save report to file.
        
        Args:
            report: Report data
            filepath: Output file path
            format: Output format (text, json, html)
            
        Returns:
            Full path of saved file
        """
        filepath = Path(filepath).expanduser()
        
        # Add appropriate extension if not present
        if format == 'json' and not filepath.suffix:
            filepath = filepath.with_suffix('.json')
        elif format == 'html' and not filepath.suffix:
            filepath = filepath.with_suffix('.html')
        elif format == 'text' and not filepath.suffix:
            filepath = filepath.with_suffix('.txt')
        
        # Generate content
        if format == 'json':
            content = self.export_json(report)
        elif format == 'html':
            content = self.export_html(report)
        else:
            content = self.export_text(report)
        
        # Write to file
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(filepath)


def generate_security_report(password: str, 
                            output_path: Optional[str] = None,
                            format: str = 'text',
                            policy_level: str = 'standard',
                            include_hashes: bool = False) -> str:
    """
    Quick function to generate a security report.
    
    Args:
        password: Password to analyze
        output_path: Optional path to save report
        format: Output format (text, json, html)
        policy_level: Policy level to validate against
        include_hashes: Whether to include hash demonstrations
        
    Returns:
        Report content as string
    """
    level_map = {
        'basic': PolicyLevel.BASIC,
        'standard': PolicyLevel.STANDARD,
        'strong': PolicyLevel.STRONG,
        'enterprise': PolicyLevel.ENTERPRISE
    }
    
    generator = SecurityReportGenerator()
    report = generator.generate_report(
        password,
        policy_level=level_map.get(policy_level.lower(), PolicyLevel.STANDARD),
        include_hashes=include_hashes
    )
    
    if output_path:
        generator.save_report(report, output_path, format)
    
    if format == 'json':
        return generator.export_json(report)
    elif format == 'html':
        return generator.export_html(report)
    else:
        return generator.export_text(report)
