"""
Password Analyzer Core Module
Analyzes password strength, entropy, and complexity.
"""

import math
import string
import re
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass, field


@dataclass
class PasswordAnalysis:
    """Data class to hold password analysis results."""
    password_length: int = 0
    has_lowercase: bool = False
    has_uppercase: bool = False
    has_digits: bool = False
    has_special: bool = False
    has_whitespace: bool = False
    charset_size: int = 0
    entropy: float = 0.0
    strength_score: int = 0  # 0-100
    strength_label: str = ""
    time_to_crack: str = ""
    weaknesses: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    pattern_warnings: List[str] = field(default_factory=list)


class PasswordAnalyzer:
    """Analyzes password strength and provides security recommendations."""
    
    # Character sets
    LOWERCASE = set(string.ascii_lowercase)
    UPPERCASE = set(string.ascii_uppercase)
    DIGITS = set(string.digits)
    SPECIAL = set(string.punctuation)
    
    # Common patterns to detect
    KEYBOARD_PATTERNS = [
        'qwerty', 'qwertz', 'azerty', 'asdfgh', 'zxcvbn',
        '12345', '123456', '1234567', '12345678', '123456789',
        'qweasd', 'asdzxc', '!@#$%', '!@#$%^'
    ]
    
    COMMON_SUBSTITUTIONS = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['7'],
        'l': ['1', '|'],
        'b': ['8'],
        'g': ['9']
    }
    
    # Strength thresholds
    STRENGTH_THRESHOLDS = [
        (0, 20, "Very Weak", "red"),
        (20, 40, "Weak", "orange"),
        (40, 60, "Fair", "yellow"),
        (60, 80, "Strong", "lightgreen"),
        (80, 101, "Very Strong", "green")
    ]
    
    def __init__(self):
        """Initialize the password analyzer."""
        self.analysis = None
    
    def analyze(self, password: str) -> PasswordAnalysis:
        """
        Perform comprehensive password analysis.
        
        Args:
            password: The password to analyze
            
        Returns:
            PasswordAnalysis object containing all analysis results
        """
        self.analysis = PasswordAnalysis()
        
        if not password:
            self.analysis.weaknesses.append("Password is empty")
            self.analysis.strength_label = "No Password"
            return self.analysis
        
        # Basic analysis
        self._analyze_length(password)
        self._analyze_character_types(password)
        self._calculate_charset_size()
        self._calculate_entropy(password)
        self._detect_patterns(password)
        self._calculate_time_to_crack()
        self._calculate_strength_score()
        self._generate_recommendations()
        
        return self.analysis
    
    def _analyze_length(self, password: str) -> None:
        """Analyze password length."""
        self.analysis.password_length = len(password)
        
        if len(password) < 8:
            self.analysis.weaknesses.append(
                f"Password is too short ({len(password)} characters). Minimum recommended is 8."
            )
        elif len(password) < 12:
            self.analysis.weaknesses.append(
                f"Password length ({len(password)}) is acceptable but 12+ characters recommended."
            )
    
    def _analyze_character_types(self, password: str) -> None:
        """Analyze which character types are present."""
        password_set = set(password)
        
        self.analysis.has_lowercase = bool(password_set & self.LOWERCASE)
        self.analysis.has_uppercase = bool(password_set & self.UPPERCASE)
        self.analysis.has_digits = bool(password_set & self.DIGITS)
        self.analysis.has_special = bool(password_set & self.SPECIAL)
        self.analysis.has_whitespace = bool(set(string.whitespace) & password_set)
        
        # Check for missing character types
        missing = []
        if not self.analysis.has_lowercase:
            missing.append("lowercase letters")
        if not self.analysis.has_uppercase:
            missing.append("uppercase letters")
        if not self.analysis.has_digits:
            missing.append("digits")
        if not self.analysis.has_special:
            missing.append("special characters")
        
        if missing:
            self.analysis.weaknesses.append(
                f"Missing character types: {', '.join(missing)}"
            )
    
    def _calculate_charset_size(self) -> None:
        """Calculate the effective character set size."""
        charset_size = 0
        
        if self.analysis.has_lowercase:
            charset_size += 26
        if self.analysis.has_uppercase:
            charset_size += 26
        if self.analysis.has_digits:
            charset_size += 10
        if self.analysis.has_special:
            charset_size += 32
        if self.analysis.has_whitespace:
            charset_size += 1
        
        self.analysis.charset_size = charset_size
    
    def _calculate_entropy(self, password: str) -> None:
        """
        Calculate password entropy.
        Entropy = length * log2(charset_size)
        """
        if self.analysis.charset_size > 0:
            self.analysis.entropy = (
                self.analysis.password_length * math.log2(self.analysis.charset_size)
            )
        else:
            self.analysis.entropy = 0.0
    
    def _detect_patterns(self, password: str) -> None:
        """Detect common patterns and weaknesses."""
        lower_password = password.lower()
        
        # Check for keyboard patterns
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in lower_password:
                self.analysis.pattern_warnings.append(
                    f"Contains keyboard pattern: '{pattern}'"
                )
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            self.analysis.pattern_warnings.append(
                "Contains repeated characters (e.g., 'aaa')"
            )
        
        # Check for sequential characters
        if self._has_sequential_chars(password, 3):
            self.analysis.pattern_warnings.append(
                "Contains sequential characters (e.g., 'abc', '123')"
            )
        
        # Check for common substitutions (leet speak)
        if self._detect_leet_speak(password):
            self.analysis.pattern_warnings.append(
                "Uses common character substitutions (l33t speak) - easily guessable"
            )
        
        # Check if password is all same case
        if password.isalpha():
            if password.islower() or password.isupper():
                self.analysis.pattern_warnings.append(
                    "Password uses only one letter case"
                )
        
        # Check for year patterns (common in passwords)
        if re.search(r'(19|20)\d{2}', password):
            self.analysis.pattern_warnings.append(
                "Contains a year pattern (e.g., '1990', '2024')"
            )
        
        # Add patterns to weaknesses
        if self.analysis.pattern_warnings:
            self.analysis.weaknesses.extend(self.analysis.pattern_warnings)
    
    def _has_sequential_chars(self, password: str, min_length: int = 3) -> bool:
        """Check for sequential characters."""
        lower = password.lower()
        
        for i in range(len(lower) - min_length + 1):
            # Check ascending sequence
            is_sequential = True
            for j in range(min_length - 1):
                if ord(lower[i + j + 1]) != ord(lower[i + j]) + 1:
                    is_sequential = False
                    break
            if is_sequential:
                return True
            
            # Check descending sequence
            is_sequential = True
            for j in range(min_length - 1):
                if ord(lower[i + j + 1]) != ord(lower[i + j]) - 1:
                    is_sequential = False
                    break
            if is_sequential:
                return True
        
        return False
    
    def _detect_leet_speak(self, password: str) -> bool:
        """Detect if password uses common character substitutions."""
        # Count substitution patterns
        substitution_count = 0
        
        for char, subs in self.COMMON_SUBSTITUTIONS.items():
            for sub in subs:
                if sub in password:
                    substitution_count += 1
        
        # If multiple substitutions found, likely using leet speak
        return substitution_count >= 2
    
    def _calculate_time_to_crack(self) -> None:
        """
        Estimate time to crack based on entropy.
        Assumes 10 billion guesses per second (modern GPU cluster).
        """
        if self.analysis.entropy <= 0:
            self.analysis.time_to_crack = "Instant"
            return
        
        # 2^entropy possible combinations
        combinations = 2 ** self.analysis.entropy
        
        # 10 billion guesses per second
        guesses_per_second = 10_000_000_000
        
        seconds = combinations / guesses_per_second
        
        self.analysis.time_to_crack = self._format_time(seconds)
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time."""
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds / 31536000)} years"
        elif seconds < 31536000 * 1000000:
            return f"{int(seconds / 31536000):,} years"
        elif seconds < 31536000 * 1e9:
            return f"{seconds / 31536000 / 1e6:.1f} million years"
        elif seconds < 31536000 * 1e12:
            return f"{seconds / 31536000 / 1e9:.1f} billion years"
        else:
            return f"{seconds / 31536000 / 1e12:.1f} trillion years"
    
    def _calculate_strength_score(self) -> None:
        """Calculate overall password strength score (0-100)."""
        score = 0
        
        # Length contribution (up to 30 points)
        length = self.analysis.password_length
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 20
        elif length >= 8:
            score += 15
        else:
            score += length * 2
        
        # Character variety contribution (up to 30 points)
        char_types = sum([
            self.analysis.has_lowercase,
            self.analysis.has_uppercase,
            self.analysis.has_digits,
            self.analysis.has_special
        ])
        score += char_types * 7.5
        
        # Entropy contribution (up to 30 points)
        entropy = self.analysis.entropy
        if entropy >= 80:
            score += 30
        elif entropy >= 60:
            score += 25
        elif entropy >= 40:
            score += 20
        elif entropy >= 28:
            score += 15
        else:
            score += entropy * 0.5
        
        # Penalty for patterns and weaknesses
        pattern_penalty = len(self.analysis.pattern_warnings) * 5
        weakness_penalty = len(self.analysis.weaknesses) * 3
        score -= pattern_penalty
        score -= weakness_penalty
        
        # Ensure score is within bounds
        self.analysis.strength_score = max(0, min(100, int(score)))
        
        # Set strength label
        for min_val, max_val, label, _ in self.STRENGTH_THRESHOLDS:
            if min_val <= self.analysis.strength_score < max_val:
                self.analysis.strength_label = label
                break
    
    def _generate_recommendations(self) -> None:
        """Generate password improvement recommendations."""
        if self.analysis.password_length < 12:
            self.analysis.recommendations.append(
                "Increase password length to at least 12 characters"
            )
        
        if not self.analysis.has_uppercase:
            self.analysis.recommendations.append(
                "Add uppercase letters (A-Z)"
            )
        
        if not self.analysis.has_lowercase:
            self.analysis.recommendations.append(
                "Add lowercase letters (a-z)"
            )
        
        if not self.analysis.has_digits:
            self.analysis.recommendations.append(
                "Add numbers (0-9)"
            )
        
        if not self.analysis.has_special:
            self.analysis.recommendations.append(
                "Add special characters (!@#$%^&*)"
            )
        
        if self.analysis.pattern_warnings:
            self.analysis.recommendations.append(
                "Avoid common patterns, keyboard sequences, and predictable substitutions"
            )
        
        if self.analysis.entropy < 60:
            self.analysis.recommendations.append(
                "Consider using a passphrase: combine 4+ random words"
            )
        
        # General recommendations
        if self.analysis.strength_score < 60:
            self.analysis.recommendations.append(
                "Consider using a password manager to generate and store strong passwords"
            )
    
    def get_strength_color(self) -> str:
        """Get the color associated with the current strength level."""
        for min_val, max_val, _, color in self.STRENGTH_THRESHOLDS:
            if min_val <= self.analysis.strength_score < max_val:
                return color
        return "gray"
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a dictionary summary of the analysis."""
        if not self.analysis:
            return {}
        
        return {
            'length': self.analysis.password_length,
            'charset_size': self.analysis.charset_size,
            'entropy': round(self.analysis.entropy, 2),
            'strength_score': self.analysis.strength_score,
            'strength_label': self.analysis.strength_label,
            'time_to_crack': self.analysis.time_to_crack,
            'character_types': {
                'lowercase': self.analysis.has_lowercase,
                'uppercase': self.analysis.has_uppercase,
                'digits': self.analysis.has_digits,
                'special': self.analysis.has_special,
            },
            'weaknesses': self.analysis.weaknesses,
            'recommendations': self.analysis.recommendations
        }


def quick_analyze(password: str) -> Dict[str, Any]:
    """
    Quick function to analyze a password and return results.
    
    Args:
        password: The password to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    analyzer = PasswordAnalyzer()
    analyzer.analyze(password)
    return analyzer.get_summary()
