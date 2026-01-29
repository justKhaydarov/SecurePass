"""
Dictionary and Common Password Checker Module
Checks passwords against common password lists and dictionary words.
"""

import os
import re
from typing import List, Set, Tuple, Optional
from pathlib import Path


class DictionaryChecker:
    """Checks passwords against dictionaries and common password lists."""
    
    # Built-in list of very common passwords (top 100)
    COMMON_PASSWORDS = {
        '123456', 'password', '12345678', 'qwerty', '123456789',
        '12345', '1234', '111111', '1234567', 'dragon',
        '123123', 'baseball', 'abc123', 'football', 'monkey',
        'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
        '123321', 'mustang', '1234567890', 'michael', '654321',
        'superman', '1qaz2wsx', '7777777', 'fuckyou', '121212',
        '000000', 'qazwsx', '123qwe', 'killer', 'trustno1',
        'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter',
        'buster', 'soccer', 'harley', 'batman', 'andrew',
        'tigger', 'sunshine', 'iloveyou', '2000', 'charlie',
        'robert', 'thomas', 'hockey', 'ranger', 'daniel',
        'starwars', 'klaster', '112233', 'george', 'computer',
        'michelle', 'jessica', 'pepper', '1111', 'zxcvbn',
        '555555', '11111111', '131313', 'freedom', '777777',
        'pass', 'maggie', '159753', 'aaaaaa', 'ginger',
        'princess', 'joshua', 'cheese', 'amanda', 'summer',
        'love', 'ashley', 'nicole', 'chelsea', 'biteme',
        'matthew', 'access', 'yankees', '987654321', 'dallas',
        'austin', 'thunder', 'taylor', 'matrix', 'admin',
        'password1', 'password123', 'welcome', 'hello', 'letmein'
    }
    
    # Common English words often used in passwords
    COMMON_WORDS = {
        'love', 'baby', 'angel', 'password', 'sunshine', 'princess',
        'welcome', 'shadow', 'superman', 'michael', 'master', 'dragon',
        'monkey', 'killer', 'soccer', 'batman', 'football', 'baseball',
        'hockey', 'ranger', 'starwars', 'computer', 'pepper', 'freedom',
        'cheese', 'summer', 'hello', 'secret', 'admin', 'login',
        'welcome', 'guest', 'user', 'test', 'pass', 'root',
        'apple', 'orange', 'banana', 'coffee', 'cookie', 'butter',
        'flower', 'garden', 'house', 'home', 'family', 'friend',
        'music', 'movie', 'video', 'game', 'play', 'sport',
        'blue', 'green', 'black', 'white', 'pink', 'purple'
    }
    
    def __init__(self, wordlist_path: Optional[str] = None):
        """
        Initialize the dictionary checker.
        
        Args:
            wordlist_path: Optional path to a custom wordlist file (e.g., RockYou)
        """
        self.custom_wordlist: Set[str] = set()
        self.wordlist_loaded = False
        self.wordlist_path = wordlist_path
        
        if wordlist_path:
            self.load_wordlist(wordlist_path)
    
    def load_wordlist(self, path: str, max_entries: int = 1000000) -> bool:
        """
        Load a wordlist from file.
        
        Args:
            path: Path to the wordlist file
            max_entries: Maximum number of entries to load
            
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            path = Path(path).expanduser()
            if not path.exists():
                print(f"Wordlist not found: {path}")
                return False
            
            count = 0
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip().lower()
                    if word and len(word) >= 3:
                        self.custom_wordlist.add(word)
                        count += 1
                        if count >= max_entries:
                            break
            
            self.wordlist_loaded = True
            print(f"Loaded {len(self.custom_wordlist)} words from wordlist")
            return True
            
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return False
    
    def check_common_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Check if password is in common passwords list.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (is_common, matched_password)
        """
        lower_password = password.lower()
        
        # Direct match
        if lower_password in self.COMMON_PASSWORDS:
            return True, lower_password
        
        # Check custom wordlist
        if self.wordlist_loaded and lower_password in self.custom_wordlist:
            return True, lower_password
        
        return False, None
    
    def check_dictionary_word(self, password: str) -> Tuple[bool, List[str]]:
        """
        Check if password contains common dictionary words.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (contains_words, list_of_found_words)
        """
        lower_password = password.lower()
        found_words = []
        
        # Check for common words
        for word in self.COMMON_WORDS:
            if len(word) >= 4 and word in lower_password:
                found_words.append(word)
        
        # Check custom wordlist for words in password
        if self.wordlist_loaded:
            for word in self.custom_wordlist:
                if len(word) >= 4 and word in lower_password:
                    if word not in found_words:
                        found_words.append(word)
                        if len(found_words) >= 10:  # Limit results
                            break
        
        return bool(found_words), found_words
    
    def check_variations(self, password: str) -> Tuple[bool, List[str]]:
        """
        Check if password is a variation of common passwords.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (is_variation, list_of_variations_found)
        """
        variations_found = []
        lower_password = password.lower()
        
        # Common substitution patterns
        substitutions = [
            ('a', ['@', '4']),
            ('e', ['3']),
            ('i', ['1', '!']),
            ('o', ['0']),
            ('s', ['$', '5']),
            ('t', ['7']),
            ('l', ['1', '|'])
        ]
        
        # Convert password back to potential original
        normalized = lower_password
        for char, subs in substitutions:
            for sub in subs:
                normalized = normalized.replace(sub, char)
        
        # Check if normalized version is a common password
        if normalized != lower_password:
            if normalized in self.COMMON_PASSWORDS:
                variations_found.append(f"'{normalized}' with character substitutions")
            
            if self.wordlist_loaded and normalized in self.custom_wordlist:
                variations_found.append(f"'{normalized}' with character substitutions")
        
        # Check for common patterns: word + numbers
        number_suffix_match = re.match(r'^([a-zA-Z]+)\d+$', password)
        if number_suffix_match:
            base_word = number_suffix_match.group(1).lower()
            if base_word in self.COMMON_PASSWORDS or base_word in self.COMMON_WORDS:
                variations_found.append(f"'{base_word}' + numbers")
        
        # Check for reversed passwords
        reversed_password = lower_password[::-1]
        if reversed_password in self.COMMON_PASSWORDS:
            variations_found.append(f"Reversed common password: '{reversed_password}'")
        
        return bool(variations_found), variations_found
    
    def full_check(self, password: str) -> dict:
        """
        Perform full dictionary and common password check.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with check results
        """
        results = {
            'is_common_password': False,
            'common_password_match': None,
            'contains_dictionary_words': False,
            'dictionary_words_found': [],
            'is_variation': False,
            'variations_found': [],
            'warnings': [],
            'risk_level': 'low'
        }
        
        # Check common passwords
        is_common, match = self.check_common_password(password)
        if is_common:
            results['is_common_password'] = True
            results['common_password_match'] = match
            results['warnings'].append(
                f"Password '{password}' is in the list of most common passwords!"
            )
            results['risk_level'] = 'critical'
        
        # Check dictionary words
        has_words, words = self.check_dictionary_word(password)
        if has_words:
            results['contains_dictionary_words'] = True
            results['dictionary_words_found'] = words
            results['warnings'].append(
                f"Password contains common words: {', '.join(words)}"
            )
            if results['risk_level'] != 'critical':
                results['risk_level'] = 'high'
        
        # Check variations
        is_variation, variations = self.check_variations(password)
        if is_variation:
            results['is_variation'] = True
            results['variations_found'] = variations
            results['warnings'].append(
                f"Password appears to be a variation of common passwords: {', '.join(variations)}"
            )
            if results['risk_level'] == 'low':
                results['risk_level'] = 'medium'
        
        return results
    
    def get_wordlist_stats(self) -> dict:
        """Get statistics about loaded wordlists."""
        return {
            'common_passwords_count': len(self.COMMON_PASSWORDS),
            'common_words_count': len(self.COMMON_WORDS),
            'custom_wordlist_loaded': self.wordlist_loaded,
            'custom_wordlist_count': len(self.custom_wordlist),
            'wordlist_path': str(self.wordlist_path) if self.wordlist_path else None
        }


def check_password_against_dictionary(password: str, wordlist_path: Optional[str] = None) -> dict:
    """
    Quick function to check a password against dictionaries.
    
    Args:
        password: Password to check
        wordlist_path: Optional path to custom wordlist
        
    Returns:
        Dictionary with check results
    """
    checker = DictionaryChecker(wordlist_path)
    return checker.full_check(password)
