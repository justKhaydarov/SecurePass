"""
Password Policy Enforcement Module
Defines and enforces password security policies.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class PolicyLevel(Enum):
    """Predefined policy strictness levels."""
    BASIC = "basic"
    STANDARD = "standard"
    STRONG = "strong"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


@dataclass
class PolicyRule:
    """Represents a single policy rule."""
    name: str
    description: str
    check_function: str  # Name of the check method
    enabled: bool = True
    parameters: Dict = field(default_factory=dict)


@dataclass
class PolicyResult:
    """Result of policy validation."""
    passed: bool
    score: int  # 0-100
    passed_rules: List[str] = field(default_factory=list)
    failed_rules: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class PasswordPolicy:
    """
    Defines and enforces password policies.
    
    Supports predefined policies (BASIC, STANDARD, STRONG, ENTERPRISE)
    and custom policy configuration.
    """
    
    # Predefined policy configurations
    POLICY_PRESETS = {
        PolicyLevel.BASIC: {
            'min_length': 6,
            'require_uppercase': False,
            'require_lowercase': True,
            'require_digit': False,
            'require_special': False,
            'max_consecutive_chars': 0,  # 0 = disabled
            'min_unique_chars': 3,
            'disallow_common_passwords': True,
            'disallow_username_in_password': False,
        },
        PolicyLevel.STANDARD: {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digit': True,
            'require_special': False,
            'max_consecutive_chars': 3,
            'min_unique_chars': 5,
            'disallow_common_passwords': True,
            'disallow_username_in_password': True,
        },
        PolicyLevel.STRONG: {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digit': True,
            'require_special': True,
            'max_consecutive_chars': 2,
            'min_unique_chars': 8,
            'disallow_common_passwords': True,
            'disallow_username_in_password': True,
        },
        PolicyLevel.ENTERPRISE: {
            'min_length': 16,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digit': True,
            'require_special': True,
            'max_consecutive_chars': 2,
            'min_unique_chars': 10,
            'disallow_common_passwords': True,
            'disallow_username_in_password': True,
            'min_entropy': 60,
            'disallow_keyboard_patterns': True,
            'disallow_sequential_chars': True,
        }
    }
    
    # Common passwords to check against
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', 'master', 'dragon', 'letmein', 'login',
        'admin', 'welcome', 'password1', 'password123'
    }
    
    # Keyboard patterns to detect
    KEYBOARD_PATTERNS = [
        'qwerty', 'qwertz', 'azerty', 'asdfgh', 'zxcvbn',
        'qweasd', '12345', '123456', '1234567'
    ]
    
    def __init__(self, level: PolicyLevel = PolicyLevel.STANDARD, 
                 custom_config: Optional[Dict] = None):
        """
        Initialize the password policy.
        
        Args:
            level: Predefined policy level
            custom_config: Custom configuration to override defaults
        """
        self.level = level
        
        if level == PolicyLevel.CUSTOM and custom_config:
            self.config = custom_config
        else:
            self.config = self.POLICY_PRESETS.get(level, self.POLICY_PRESETS[PolicyLevel.STANDARD]).copy()
            
            if custom_config:
                self.config.update(custom_config)
    
    def validate(self, password: str, username: Optional[str] = None) -> PolicyResult:
        """
        Validate a password against the policy.
        
        Args:
            password: Password to validate
            username: Optional username to check against
            
        Returns:
            PolicyResult with validation details
        """
        result = PolicyResult(passed=True, score=100)
        
        # Run all checks
        self._check_length(password, result)
        self._check_uppercase(password, result)
        self._check_lowercase(password, result)
        self._check_digit(password, result)
        self._check_special(password, result)
        self._check_consecutive_chars(password, result)
        self._check_unique_chars(password, result)
        self._check_common_passwords(password, result)
        
        if username:
            self._check_username_in_password(password, username, result)
        
        if self.config.get('disallow_keyboard_patterns'):
            self._check_keyboard_patterns(password, result)
        
        if self.config.get('disallow_sequential_chars'):
            self._check_sequential_chars(password, result)
        
        if self.config.get('min_entropy'):
            self._check_entropy(password, result)
        
        # Calculate final score
        if result.failed_rules:
            result.passed = False
            penalty = len(result.failed_rules) * 15
            result.score = max(0, result.score - penalty)
        
        # Add recommendations
        self._generate_recommendations(password, result)
        
        return result
    
    def _check_length(self, password: str, result: PolicyResult) -> None:
        """Check minimum length requirement."""
        min_length = self.config.get('min_length', 8)
        
        if len(password) >= min_length:
            result.passed_rules.append(f"Length >= {min_length} characters")
        else:
            result.failed_rules.append(
                f"Password must be at least {min_length} characters (currently {len(password)})"
            )
    
    def _check_uppercase(self, password: str, result: PolicyResult) -> None:
        """Check uppercase letter requirement."""
        if not self.config.get('require_uppercase'):
            return
        
        if re.search(r'[A-Z]', password):
            result.passed_rules.append("Contains uppercase letter")
        else:
            result.failed_rules.append("Password must contain at least one uppercase letter")
    
    def _check_lowercase(self, password: str, result: PolicyResult) -> None:
        """Check lowercase letter requirement."""
        if not self.config.get('require_lowercase'):
            return
        
        if re.search(r'[a-z]', password):
            result.passed_rules.append("Contains lowercase letter")
        else:
            result.failed_rules.append("Password must contain at least one lowercase letter")
    
    def _check_digit(self, password: str, result: PolicyResult) -> None:
        """Check digit requirement."""
        if not self.config.get('require_digit'):
            return
        
        if re.search(r'\d', password):
            result.passed_rules.append("Contains digit")
        else:
            result.failed_rules.append("Password must contain at least one digit")
    
    def _check_special(self, password: str, result: PolicyResult) -> None:
        """Check special character requirement."""
        if not self.config.get('require_special'):
            return
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`~]', password):
            result.passed_rules.append("Contains special character")
        else:
            result.failed_rules.append("Password must contain at least one special character")
    
    def _check_consecutive_chars(self, password: str, result: PolicyResult) -> None:
        """Check for repeated consecutive characters."""
        max_consecutive = self.config.get('max_consecutive_chars', 0)
        
        if max_consecutive <= 0:
            return
        
        pattern = r'(.)\1{' + str(max_consecutive) + r',}'
        if re.search(pattern, password):
            result.failed_rules.append(
                f"Password cannot have more than {max_consecutive} consecutive identical characters"
            )
        else:
            result.passed_rules.append("No excessive consecutive characters")
    
    def _check_unique_chars(self, password: str, result: PolicyResult) -> None:
        """Check minimum unique characters."""
        min_unique = self.config.get('min_unique_chars', 0)
        
        if min_unique <= 0:
            return
        
        unique_count = len(set(password))
        
        if unique_count >= min_unique:
            result.passed_rules.append(f"Has {unique_count} unique characters")
        else:
            result.failed_rules.append(
                f"Password must have at least {min_unique} unique characters (currently {unique_count})"
            )
    
    def _check_common_passwords(self, password: str, result: PolicyResult) -> None:
        """Check against common password list."""
        if not self.config.get('disallow_common_passwords'):
            return
        
        if password.lower() in self.COMMON_PASSWORDS:
            result.failed_rules.append("Password is too common and easily guessable")
        else:
            result.passed_rules.append("Not a commonly used password")
    
    def _check_username_in_password(self, password: str, username: str, 
                                    result: PolicyResult) -> None:
        """Check if username is contained in password."""
        if not self.config.get('disallow_username_in_password'):
            return
        
        if username and username.lower() in password.lower():
            result.failed_rules.append("Password cannot contain your username")
        else:
            result.passed_rules.append("Password does not contain username")
    
    def _check_keyboard_patterns(self, password: str, result: PolicyResult) -> None:
        """Check for keyboard patterns."""
        lower_password = password.lower()
        
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in lower_password:
                result.failed_rules.append(
                    f"Password contains keyboard pattern: '{pattern}'"
                )
                return
        
        result.passed_rules.append("No keyboard patterns detected")
    
    def _check_sequential_chars(self, password: str, result: PolicyResult) -> None:
        """Check for sequential characters (abc, 123, etc.)."""
        lower = password.lower()
        
        for i in range(len(lower) - 2):
            # Check ascending sequence
            if (ord(lower[i + 1]) == ord(lower[i]) + 1 and 
                ord(lower[i + 2]) == ord(lower[i]) + 2):
                result.failed_rules.append(
                    "Password contains sequential characters (e.g., abc, 123)"
                )
                return
            
            # Check descending sequence
            if (ord(lower[i + 1]) == ord(lower[i]) - 1 and 
                ord(lower[i + 2]) == ord(lower[i]) - 2):
                result.failed_rules.append(
                    "Password contains sequential characters (e.g., cba, 321)"
                )
                return
        
        result.passed_rules.append("No sequential characters detected")
    
    def _check_entropy(self, password: str, result: PolicyResult) -> None:
        """Check minimum entropy requirement."""
        import math
        
        min_entropy = self.config.get('min_entropy', 0)
        
        if min_entropy <= 0:
            return
        
        # Calculate charset size
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
        else:
            entropy = 0
        
        if entropy >= min_entropy:
            result.passed_rules.append(f"Entropy ({entropy:.1f} bits) meets requirement")
        else:
            result.failed_rules.append(
                f"Password entropy ({entropy:.1f} bits) is below minimum ({min_entropy} bits)"
            )
    
    def _generate_recommendations(self, password: str, result: PolicyResult) -> None:
        """Generate improvement recommendations."""
        if len(password) < 12:
            result.recommendations.append("Consider using a longer password (12+ characters)")
        
        if len(password) < 16:
            result.recommendations.append("For maximum security, use 16+ characters")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`~]', password):
            result.recommendations.append("Adding special characters increases strength")
        
        if len(set(password)) < len(password) * 0.6:
            result.recommendations.append("Use more varied characters")
        
        if result.passed and not result.warnings:
            result.recommendations.append("Consider using a password manager")
    
    def get_policy_summary(self) -> Dict:
        """Get a summary of the current policy configuration."""
        return {
            'level': self.level.value,
            'config': self.config.copy()
        }
    
    def get_requirements_text(self) -> str:
        """Get human-readable policy requirements."""
        requirements = []
        
        min_length = self.config.get('min_length', 8)
        requirements.append(f"• Minimum {min_length} characters")
        
        if self.config.get('require_uppercase'):
            requirements.append("• At least one uppercase letter (A-Z)")
        
        if self.config.get('require_lowercase'):
            requirements.append("• At least one lowercase letter (a-z)")
        
        if self.config.get('require_digit'):
            requirements.append("• At least one number (0-9)")
        
        if self.config.get('require_special'):
            requirements.append("• At least one special character (!@#$%...)")
        
        if self.config.get('min_unique_chars', 0) > 0:
            requirements.append(f"• At least {self.config['min_unique_chars']} unique characters")
        
        if self.config.get('disallow_common_passwords'):
            requirements.append("• Cannot be a commonly used password")
        
        if self.config.get('disallow_keyboard_patterns'):
            requirements.append("• No keyboard patterns (qwerty, etc.)")
        
        return "\n".join(requirements)


def validate_password(password: str, policy_level: str = 'standard',
                     username: Optional[str] = None) -> PolicyResult:
    """
    Quick function to validate a password against a policy.
    
    Args:
        password: Password to validate
        policy_level: Policy level (basic, standard, strong, enterprise)
        username: Optional username
        
    Returns:
        PolicyResult with validation details
    """
    level_map = {
        'basic': PolicyLevel.BASIC,
        'standard': PolicyLevel.STANDARD,
        'strong': PolicyLevel.STRONG,
        'enterprise': PolicyLevel.ENTERPRISE
    }
    
    level = level_map.get(policy_level.lower(), PolicyLevel.STANDARD)
    policy = PasswordPolicy(level)
    
    return policy.validate(password, username)
