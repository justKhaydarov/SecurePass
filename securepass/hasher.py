"""
Password Hashing Module
Demonstrates different hashing algorithms: MD5, SHA-256, and bcrypt.
"""

import hashlib
import os
import time
from typing import Dict, Tuple, Optional
from dataclasses import dataclass


# Try to import bcrypt, handle if not available
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("Warning: bcrypt not installed. Install with: pip install bcrypt")


@dataclass
class HashResult:
    """Data class to hold hash results."""
    algorithm: str
    hash_value: str
    salt: Optional[str]
    time_taken: float
    is_secure: bool
    notes: str


class PasswordHasher:
    """Demonstrates password hashing using various algorithms."""
    
    ALGORITHMS = {
        'md5': {
            'name': 'MD5',
            'secure': False,
            'description': 'Fast but cryptographically broken. Never use for passwords.',
            'use_case': 'File integrity checks only'
        },
        'sha1': {
            'name': 'SHA-1',
            'secure': False,
            'description': 'Deprecated. Collision attacks exist.',
            'use_case': 'Legacy systems only'
        },
        'sha256': {
            'name': 'SHA-256',
            'secure': False,  # Not secure for password hashing (too fast)
            'description': 'Secure for general hashing but too fast for passwords.',
            'use_case': 'Data integrity, digital signatures'
        },
        'sha512': {
            'name': 'SHA-512',
            'secure': False,  # Not secure for password hashing (too fast)
            'description': 'Secure for general hashing but too fast for passwords.',
            'use_case': 'Data integrity, digital signatures'
        },
        'bcrypt': {
            'name': 'bcrypt',
            'secure': True,
            'description': 'Designed for password hashing. Intentionally slow.',
            'use_case': 'Password storage (recommended)'
        }
    }
    
    def __init__(self, bcrypt_rounds: int = 12):
        """
        Initialize the password hasher.
        
        Args:
            bcrypt_rounds: Cost factor for bcrypt (4-31, default 12)
        """
        self.bcrypt_rounds = min(max(bcrypt_rounds, 4), 31)
    
    def hash_md5(self, password: str, salt: Optional[str] = None) -> HashResult:
        """
        Hash password using MD5.
        
        WARNING: MD5 is NOT secure for password hashing!
        
        Args:
            password: Password to hash
            salt: Optional salt (generated if not provided)
            
        Returns:
            HashResult with hash details
        """
        start_time = time.time()
        
        if salt is None:
            salt = os.urandom(16).hex()
        
        salted_password = salt + password
        hash_value = hashlib.md5(salted_password.encode()).hexdigest()
        
        time_taken = time.time() - start_time
        
        return HashResult(
            algorithm='MD5',
            hash_value=hash_value,
            salt=salt,
            time_taken=time_taken,
            is_secure=False,
            notes='⚠️ MD5 is cryptographically broken. Do NOT use for passwords!'
        )
    
    def hash_sha1(self, password: str, salt: Optional[str] = None) -> HashResult:
        """
        Hash password using SHA-1.
        
        WARNING: SHA-1 is deprecated and not secure!
        
        Args:
            password: Password to hash
            salt: Optional salt
            
        Returns:
            HashResult with hash details
        """
        start_time = time.time()
        
        if salt is None:
            salt = os.urandom(16).hex()
        
        salted_password = salt + password
        hash_value = hashlib.sha1(salted_password.encode()).hexdigest()
        
        time_taken = time.time() - start_time
        
        return HashResult(
            algorithm='SHA-1',
            hash_value=hash_value,
            salt=salt,
            time_taken=time_taken,
            is_secure=False,
            notes='⚠️ SHA-1 is deprecated. Collision attacks exist.'
        )
    
    def hash_sha256(self, password: str, salt: Optional[str] = None) -> HashResult:
        """
        Hash password using SHA-256.
        
        Note: SHA-256 is secure for general hashing but too fast for passwords.
        
        Args:
            password: Password to hash
            salt: Optional salt
            
        Returns:
            HashResult with hash details
        """
        start_time = time.time()
        
        if salt is None:
            salt = os.urandom(16).hex()
        
        salted_password = salt + password
        hash_value = hashlib.sha256(salted_password.encode()).hexdigest()
        
        time_taken = time.time() - start_time
        
        return HashResult(
            algorithm='SHA-256',
            hash_value=hash_value,
            salt=salt,
            time_taken=time_taken,
            is_secure=False,
            notes='SHA-256 is too fast for password hashing. Use bcrypt instead.'
        )
    
    def hash_sha512(self, password: str, salt: Optional[str] = None) -> HashResult:
        """
        Hash password using SHA-512.
        
        Args:
            password: Password to hash
            salt: Optional salt
            
        Returns:
            HashResult with hash details
        """
        start_time = time.time()
        
        if salt is None:
            salt = os.urandom(16).hex()
        
        salted_password = salt + password
        hash_value = hashlib.sha512(salted_password.encode()).hexdigest()
        
        time_taken = time.time() - start_time
        
        return HashResult(
            algorithm='SHA-512',
            hash_value=hash_value,
            salt=salt,
            time_taken=time_taken,
            is_secure=False,
            notes='SHA-512 is too fast for password hashing. Use bcrypt instead.'
        )
    
    def hash_bcrypt(self, password: str, rounds: Optional[int] = None) -> HashResult:
        """
        Hash password using bcrypt.
        
        This is the RECOMMENDED method for password hashing.
        
        Args:
            password: Password to hash
            rounds: Cost factor (uses default if not specified)
            
        Returns:
            HashResult with hash details
        """
        if not BCRYPT_AVAILABLE:
            return HashResult(
                algorithm='bcrypt',
                hash_value='ERROR: bcrypt not installed',
                salt=None,
                time_taken=0,
                is_secure=True,
                notes='Install bcrypt: pip install bcrypt'
            )
        
        start_time = time.time()
        
        if rounds is None:
            rounds = self.bcrypt_rounds
        
        # bcrypt generates its own salt
        salt = bcrypt.gensalt(rounds=rounds)
        hash_value = bcrypt.hashpw(password.encode(), salt)
        
        time_taken = time.time() - start_time
        
        return HashResult(
            algorithm='bcrypt',
            hash_value=hash_value.decode(),
            salt=salt.decode(),
            time_taken=time_taken,
            is_secure=True,
            notes=f'✓ bcrypt is secure for password hashing (cost factor: {rounds})'
        )
    
    def hash_all(self, password: str) -> Dict[str, HashResult]:
        """
        Hash password with all available algorithms.
        
        Args:
            password: Password to hash
            
        Returns:
            Dictionary of algorithm name to HashResult
        """
        results = {}
        
        results['md5'] = self.hash_md5(password)
        results['sha1'] = self.hash_sha1(password)
        results['sha256'] = self.hash_sha256(password)
        results['sha512'] = self.hash_sha512(password)
        results['bcrypt'] = self.hash_bcrypt(password)
        
        return results
    
    def verify_bcrypt(self, password: str, hash_value: str) -> Tuple[bool, float]:
        """
        Verify a password against a bcrypt hash.
        
        Args:
            password: Password to verify
            hash_value: bcrypt hash to verify against
            
        Returns:
            Tuple of (is_valid, time_taken)
        """
        if not BCRYPT_AVAILABLE:
            raise RuntimeError("bcrypt not installed")
        
        start_time = time.time()
        
        try:
            is_valid = bcrypt.checkpw(password.encode(), hash_value.encode())
        except Exception:
            is_valid = False
        
        time_taken = time.time() - start_time
        
        return is_valid, time_taken
    
    def demonstrate_timing(self, password: str) -> Dict[str, float]:
        """
        Demonstrate the time difference between algorithms.
        
        Args:
            password: Password to hash
            
        Returns:
            Dictionary of algorithm name to time taken
        """
        timings = {}
        
        # Hash multiple times for more accurate measurement
        iterations = 100
        
        # MD5
        start = time.time()
        for _ in range(iterations):
            hashlib.md5(password.encode()).hexdigest()
        timings['MD5'] = (time.time() - start) / iterations
        
        # SHA-256
        start = time.time()
        for _ in range(iterations):
            hashlib.sha256(password.encode()).hexdigest()
        timings['SHA-256'] = (time.time() - start) / iterations
        
        # SHA-512
        start = time.time()
        for _ in range(iterations):
            hashlib.sha512(password.encode()).hexdigest()
        timings['SHA-512'] = (time.time() - start) / iterations
        
        # bcrypt (only 1 iteration due to intentional slowness)
        if BCRYPT_AVAILABLE:
            start = time.time()
            bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=self.bcrypt_rounds))
            timings['bcrypt'] = time.time() - start
        
        return timings
    
    def get_algorithm_info(self) -> Dict[str, dict]:
        """Get information about all supported algorithms."""
        return self.ALGORITHMS.copy()
    
    def compare_hashes(self, password: str) -> str:
        """
        Generate a formatted comparison of all hash algorithms.
        
        Args:
            password: Password to hash
            
        Returns:
            Formatted string comparing all algorithms
        """
        results = self.hash_all(password)
        
        output = ["=" * 70]
        output.append("PASSWORD HASHING COMPARISON")
        output.append("=" * 70)
        output.append(f"Password: {'*' * len(password)} ({len(password)} characters)")
        output.append("-" * 70)
        
        for algo, result in results.items():
            output.append(f"\n{result.algorithm}:")
            output.append(f"  Hash: {result.hash_value[:64]}...")
            if result.salt:
                output.append(f"  Salt: {result.salt[:32]}...")
            output.append(f"  Time: {result.time_taken*1000:.4f} ms")
            output.append(f"  Secure: {'Yes ✓' if result.is_secure else 'No ✗'}")
            output.append(f"  Note: {result.notes}")
        
        output.append("\n" + "=" * 70)
        output.append("RECOMMENDATION: Always use bcrypt for password storage!")
        output.append("=" * 70)
        
        return "\n".join(output)


def hash_password(password: str, algorithm: str = 'bcrypt') -> HashResult:
    """
    Quick function to hash a password.
    
    Args:
        password: Password to hash
        algorithm: Algorithm to use (md5, sha256, sha512, bcrypt)
        
    Returns:
        HashResult with hash details
    """
    hasher = PasswordHasher()
    
    algorithm = algorithm.lower()
    if algorithm == 'md5':
        return hasher.hash_md5(password)
    elif algorithm == 'sha1':
        return hasher.hash_sha1(password)
    elif algorithm == 'sha256':
        return hasher.hash_sha256(password)
    elif algorithm == 'sha512':
        return hasher.hash_sha512(password)
    elif algorithm == 'bcrypt':
        return hasher.hash_bcrypt(password)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
