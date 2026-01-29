"""
Password Cracking Simulation Module
Demonstrates how attackers exploit weak passwords (educational purposes only).
"""

import hashlib
import time
import string
import itertools
from typing import Optional, Callable, Generator, Tuple, List
from dataclasses import dataclass
from pathlib import Path

# Try to import bcrypt
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


@dataclass
class CrackResult:
    """Data class to hold cracking attempt results."""
    success: bool
    password: Optional[str]
    attempts: int
    time_taken: float
    method: str
    hash_type: str


class PasswordCracker:
    """
    Demonstrates password cracking techniques.
    
    WARNING: This is for EDUCATIONAL PURPOSES ONLY.
    Never use these techniques against systems you don't own.
    """
    
    # Built-in list of common passwords for demonstration
    DEMO_PASSWORDS = [
        '123456', 'password', '12345678', 'qwerty', '123456789',
        '12345', '1234', '111111', '1234567', 'dragon',
        '123123', 'baseball', 'abc123', 'football', 'monkey',
        'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
        'password1', 'password123', 'admin', 'root', 'toor',
        'pass', 'test', 'guest', 'master', 'changeme',
        'hello', 'love', 'princess', 'welcome', 'login'
    ]
    
    def __init__(self, wordlist_path: Optional[str] = None, max_attempts: int = 1000000):
        """
        Initialize the password cracker.
        
        Args:
            wordlist_path: Path to wordlist file (e.g., rockyou.txt)
            max_attempts: Maximum number of attempts before giving up
        """
        self.wordlist_path = wordlist_path
        self.max_attempts = max_attempts
        self.wordlist: List[str] = []
        self._load_wordlist()
    
    def _load_wordlist(self) -> None:
        """Load wordlist from file if provided."""
        if self.wordlist_path:
            try:
                path = Path(self.wordlist_path).expanduser()
                if path.exists():
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        self.wordlist = [line.strip() for line in f if line.strip()][:self.max_attempts]
                    print(f"Loaded {len(self.wordlist)} passwords from wordlist")
            except Exception as e:
                print(f"Error loading wordlist: {e}")
    
    def _get_hash_function(self, hash_type: str) -> Callable[[str], str]:
        """Get the appropriate hash function."""
        hash_type = hash_type.lower()
        
        if hash_type == 'md5':
            return lambda p: hashlib.md5(p.encode()).hexdigest()
        elif hash_type == 'sha1':
            return lambda p: hashlib.sha1(p.encode()).hexdigest()
        elif hash_type == 'sha256':
            return lambda p: hashlib.sha256(p.encode()).hexdigest()
        elif hash_type == 'sha512':
            return lambda p: hashlib.sha512(p.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def dictionary_attack(
        self,
        target_hash: str,
        hash_type: str = 'md5',
        callback: Optional[Callable[[int, str], None]] = None
    ) -> CrackResult:
        """
        Attempt to crack a hash using dictionary attack.
        
        Args:
            target_hash: The hash to crack
            hash_type: Type of hash (md5, sha1, sha256, sha512)
            callback: Optional callback function(attempts, current_word)
            
        Returns:
            CrackResult with attack results
        """
        start_time = time.time()
        hash_func = self._get_hash_function(hash_type)
        attempts = 0
        
        # Use loaded wordlist or demo passwords
        passwords_to_try = self.wordlist if self.wordlist else self.DEMO_PASSWORDS
        
        for password in passwords_to_try:
            attempts += 1
            
            if callback and attempts % 1000 == 0:
                callback(attempts, password)
            
            if hash_func(password) == target_hash.lower():
                return CrackResult(
                    success=True,
                    password=password,
                    attempts=attempts,
                    time_taken=time.time() - start_time,
                    method='Dictionary Attack',
                    hash_type=hash_type.upper()
                )
            
            if attempts >= self.max_attempts:
                break
        
        return CrackResult(
            success=False,
            password=None,
            attempts=attempts,
            time_taken=time.time() - start_time,
            method='Dictionary Attack',
            hash_type=hash_type.upper()
        )
    
    def brute_force_attack(
        self,
        target_hash: str,
        hash_type: str = 'md5',
        charset: str = 'lowercase',
        min_length: int = 1,
        max_length: int = 4,
        callback: Optional[Callable[[int, str], None]] = None
    ) -> CrackResult:
        """
        Attempt to crack a hash using brute force.
        
        WARNING: This is very slow for passwords longer than 4-5 characters!
        
        Args:
            target_hash: The hash to crack
            hash_type: Type of hash (md5, sha1, sha256, sha512)
            charset: Character set to use (lowercase, uppercase, digits, all)
            min_length: Minimum password length to try
            max_length: Maximum password length to try
            callback: Optional callback function(attempts, current_word)
            
        Returns:
            CrackResult with attack results
        """
        start_time = time.time()
        hash_func = self._get_hash_function(hash_type)
        attempts = 0
        
        # Select character set
        if charset == 'lowercase':
            chars = string.ascii_lowercase
        elif charset == 'uppercase':
            chars = string.ascii_uppercase
        elif charset == 'digits':
            chars = string.digits
        elif charset == 'alphanumeric':
            chars = string.ascii_letters + string.digits
        elif charset == 'all':
            chars = string.ascii_letters + string.digits + string.punctuation
        else:
            chars = charset
        
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(chars, repeat=length):
                password = ''.join(combination)
                attempts += 1
                
                if callback and attempts % 10000 == 0:
                    callback(attempts, password)
                
                if hash_func(password) == target_hash.lower():
                    return CrackResult(
                        success=True,
                        password=password,
                        attempts=attempts,
                        time_taken=time.time() - start_time,
                        method=f'Brute Force ({charset})',
                        hash_type=hash_type.upper()
                    )
                
                if attempts >= self.max_attempts:
                    return CrackResult(
                        success=False,
                        password=None,
                        attempts=attempts,
                        time_taken=time.time() - start_time,
                        method=f'Brute Force ({charset})',
                        hash_type=hash_type.upper()
                    )
        
        return CrackResult(
            success=False,
            password=None,
            attempts=attempts,
            time_taken=time.time() - start_time,
            method=f'Brute Force ({charset})',
            hash_type=hash_type.upper()
        )
    
    def rule_based_attack(
        self,
        target_hash: str,
        hash_type: str = 'md5',
        base_words: Optional[List[str]] = None,
        callback: Optional[Callable[[int, str], None]] = None
    ) -> CrackResult:
        """
        Attempt to crack using rule-based mutations.
        
        Applies common password transformations like:
        - Adding numbers at the end
        - Capitalizing first letter
        - Common substitutions (a->@, e->3, etc.)
        
        Args:
            target_hash: The hash to crack
            hash_type: Type of hash
            base_words: List of base words to mutate
            callback: Optional callback function
            
        Returns:
            CrackResult with attack results
        """
        start_time = time.time()
        hash_func = self._get_hash_function(hash_type)
        attempts = 0
        
        if base_words is None:
            base_words = self.DEMO_PASSWORDS[:20]
        
        def generate_mutations(word: str) -> Generator[str, None, None]:
            """Generate common password mutations."""
            yield word
            yield word.lower()
            yield word.upper()
            yield word.capitalize()
            yield word.swapcase()
            
            # Add numbers
            for i in range(100):
                yield f"{word}{i}"
                yield f"{word}{i:02d}"
            
            # Add years
            for year in range(1980, 2030):
                yield f"{word}{year}"
            
            # Add common suffixes
            for suffix in ['!', '!!', '!!!', '@', '#', '$', '123', '1234', '12345']:
                yield f"{word}{suffix}"
            
            # Leet speak substitutions
            leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
            leet_word = word
            for char, replacement in leet_map.items():
                leet_word = leet_word.replace(char, replacement)
            if leet_word != word:
                yield leet_word
        
        for word in base_words:
            for mutation in generate_mutations(word):
                attempts += 1
                
                if callback and attempts % 1000 == 0:
                    callback(attempts, mutation)
                
                if hash_func(mutation) == target_hash.lower():
                    return CrackResult(
                        success=True,
                        password=mutation,
                        attempts=attempts,
                        time_taken=time.time() - start_time,
                        method='Rule-based Attack',
                        hash_type=hash_type.upper()
                    )
                
                if attempts >= self.max_attempts:
                    break
        
        return CrackResult(
            success=False,
            password=None,
            attempts=attempts,
            time_taken=time.time() - start_time,
            method='Rule-based Attack',
            hash_type=hash_type.upper()
        )
    
    def crack_bcrypt(
        self,
        target_hash: str,
        passwords: Optional[List[str]] = None,
        callback: Optional[Callable[[int, str], None]] = None
    ) -> CrackResult:
        """
        Attempt to crack a bcrypt hash.
        
        Note: bcrypt is intentionally slow, so this will take much longer!
        
        Args:
            target_hash: The bcrypt hash to crack
            passwords: List of passwords to try
            callback: Optional callback function
            
        Returns:
            CrackResult with attack results
        """
        if not BCRYPT_AVAILABLE:
            return CrackResult(
                success=False,
                password=None,
                attempts=0,
                time_taken=0,
                method='bcrypt Dictionary Attack',
                hash_type='bcrypt'
            )
        
        start_time = time.time()
        attempts = 0
        
        if passwords is None:
            passwords = self.wordlist if self.wordlist else self.DEMO_PASSWORDS
        
        # Limit attempts for bcrypt due to slowness
        max_bcrypt_attempts = min(len(passwords), 1000)
        
        for password in passwords[:max_bcrypt_attempts]:
            attempts += 1
            
            if callback:
                callback(attempts, password)
            
            try:
                if bcrypt.checkpw(password.encode(), target_hash.encode()):
                    return CrackResult(
                        success=True,
                        password=password,
                        attempts=attempts,
                        time_taken=time.time() - start_time,
                        method='bcrypt Dictionary Attack',
                        hash_type='bcrypt'
                    )
            except Exception:
                continue
        
        return CrackResult(
            success=False,
            password=None,
            attempts=attempts,
            time_taken=time.time() - start_time,
            method='bcrypt Dictionary Attack',
            hash_type='bcrypt'
        )
    
    def demonstrate_crack(self, password: str, hash_type: str = 'md5') -> str:
        """
        Demonstrate cracking a password for educational purposes.
        
        Args:
            password: Password to hash and attempt to crack
            hash_type: Hash algorithm to use
            
        Returns:
            Formatted string showing the demonstration results
        """
        output = []
        output.append("=" * 70)
        output.append("PASSWORD CRACKING DEMONSTRATION")
        output.append("⚠️  FOR EDUCATIONAL PURPOSES ONLY  ⚠️")
        output.append("=" * 70)
        
        # Generate hash
        if hash_type.lower() == 'bcrypt':
            if not BCRYPT_AVAILABLE:
                return "bcrypt not available. Install with: pip install bcrypt"
            target_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
        else:
            hash_func = self._get_hash_function(hash_type)
            target_hash = hash_func(password)
        
        output.append(f"\nOriginal Password: {'*' * len(password)}")
        output.append(f"Hash Type: {hash_type.upper()}")
        output.append(f"Target Hash: {target_hash[:64]}...")
        output.append("-" * 70)
        
        # Try dictionary attack
        output.append("\n[1] Attempting Dictionary Attack...")
        if hash_type.lower() == 'bcrypt':
            result = self.crack_bcrypt(target_hash)
        else:
            result = self.dictionary_attack(target_hash, hash_type)
        
        if result.success:
            output.append(f"    ✓ SUCCESS! Password found: {result.password}")
            output.append(f"    Attempts: {result.attempts:,}")
            output.append(f"    Time: {result.time_taken:.4f} seconds")
        else:
            output.append(f"    ✗ Failed after {result.attempts:,} attempts")
            
            # Only try brute force for non-bcrypt and short passwords
            if hash_type.lower() != 'bcrypt' and len(password) <= 4:
                output.append("\n[2] Attempting Brute Force Attack (short passwords only)...")
                result = self.brute_force_attack(
                    target_hash, hash_type,
                    charset='alphanumeric',
                    max_length=4
                )
                
                if result.success:
                    output.append(f"    ✓ SUCCESS! Password found: {result.password}")
                    output.append(f"    Attempts: {result.attempts:,}")
                    output.append(f"    Time: {result.time_taken:.4f} seconds")
                else:
                    output.append(f"    ✗ Failed after {result.attempts:,} attempts")
        
        output.append("\n" + "=" * 70)
        output.append("LESSON: Strong, unique passwords are essential!")
        output.append("Use a password manager and enable 2FA where possible.")
        output.append("=" * 70)
        
        return "\n".join(output)
    
    def estimate_crack_time(self, password_length: int, charset_size: int, 
                            guesses_per_second: int = 10_000_000_000) -> dict:
        """
        Estimate time to crack a password via brute force.
        
        Args:
            password_length: Length of password
            charset_size: Size of character set
            guesses_per_second: Assumed guessing rate (default 10 billion)
            
        Returns:
            Dictionary with time estimates
        """
        combinations = charset_size ** password_length
        seconds = combinations / guesses_per_second
        
        return {
            'combinations': combinations,
            'guesses_per_second': guesses_per_second,
            'seconds': seconds,
            'minutes': seconds / 60,
            'hours': seconds / 3600,
            'days': seconds / 86400,
            'years': seconds / 31536000,
            'readable': self._format_time(seconds)
        }
    
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
        else:
            years = seconds / 31536000
            if years < 1000:
                return f"{int(years)} years"
            elif years < 1e6:
                return f"{years/1000:.1f} thousand years"
            elif years < 1e9:
                return f"{years/1e6:.1f} million years"
            else:
                return f"{years/1e9:.1f} billion years"


def simulate_crack(password: str, hash_type: str = 'md5') -> str:
    """
    Quick function to demonstrate password cracking.
    
    Args:
        password: Password to crack
        hash_type: Hash algorithm
        
    Returns:
        Demonstration results
    """
    cracker = PasswordCracker()
    return cracker.demonstrate_crack(password, hash_type)
