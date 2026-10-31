"""
Core Password Strength Analyzer Module.
Evaluates password length, character complexity, Shannon entropy, pool entropy,
character uniqueness, sequential/keyboard patterns, and common breached passwords.
"""

import math
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
    "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321",
    "pussy", "superman", "1qaz2wsx", "7777777", "fuckyou", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew",
    "tigger", "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233",
    "george", "asshole", "computer", "michelle", "jessica", "pepper", "1111",
    "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass",
    "fuck", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "admin", "password123", "welcome", "india123"
}

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890"
]


@dataclass
class AnalysisResult:
    password_length: int
    unique_chars: int
    uniqueness_ratio: float
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    pool_entropy_bits: float
    shannon_entropy_bits: float
    score: int  # 0 to 100
    rating: str  # Very Weak, Weak, Moderate, Strong, Very Strong
    estimated_crack_time: str
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "password_length": self.password_length,
            "unique_chars": self.unique_chars,
            "uniqueness_ratio": round(self.uniqueness_ratio, 2),
            "has_lowercase": self.has_lowercase,
            "has_uppercase": self.has_uppercase,
            "has_digits": self.has_digits,
            "has_special": self.has_special,
            "pool_entropy_bits": round(self.pool_entropy_bits, 2),
            "shannon_entropy_bits": round(self.shannon_entropy_bits, 2),
            "score": self.score,
            "rating": self.rating,
            "estimated_crack_time": self.estimated_crack_time,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.recommendations,
        }


class PasswordAnalyzer:
    """Evaluates password strength using cryptographic entropy and heuristic pattern detection."""

    @staticmethod
    def calculate_pool_entropy(password: str) -> float:
        """
        Calculates standard pool entropy: E = L * log2(R)
        where L is password length and R is the size of the character pool used.
        """
        if not password:
            return 0.0
        pool_size = 0
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(not c.isalnum() for c in password):
            pool_size += 32

        if pool_size == 0:
            return 0.0
        return len(password) * math.log2(pool_size)

    @staticmethod
    def calculate_shannon_entropy(password: str) -> float:
        """
        Calculates total Shannon information entropy in bits across the string,
        penalizing character repetition.
        """
        if not password:
            return 0.0
        length = len(password)
        frequencies = {}
        for char in password:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy_per_char = -sum(
            (count / length) * math.log2(count / length)
            for count in frequencies.values()
        )
        return entropy_per_char * length

    @staticmethod
    def estimate_crack_time(entropy_bits: float) -> str:
        """
        Estimates offline brute-force crack time assuming an attacker rate of
        10^10 guesses/second (modern GPU cluster against fast hash).
        """
        if entropy_bits <= 0:
            return "Instant"
        guesses = 2 ** entropy_bits
        guesses_per_sec = 1e10  # 10 billion guesses/sec
        seconds = guesses / (2 * guesses_per_sec)  # Average 50% keyspace search

        if seconds < 1:
            return "Instant (< 1 second)"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds // 86400)} days"
        elif seconds < 31536000 * 1000:
            return f"{int(seconds // 31536000)} years"
        elif seconds < 31536000 * 1e6:
            return f"{int(seconds // (31536000 * 1000))} millennia"
        else:
            return "Centuries+ (Cryptographically unfeasible)"

    @classmethod
    def _detect_sequences(cls, password: str) -> bool:
        """Detects 3+ sequential alphabetical, numerical, or keyboard sequences."""
        lower_pw = password.lower()
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789",
            *KEYBOARD_ROWS
        ]
        for seq in sequences:
            for i in range(len(seq) - 2):
                sub = seq[i:i + 3]
                if sub in lower_pw or sub[::-1] in lower_pw:
                    return True
        return False

    @classmethod
    def analyze(cls, password: str) -> AnalysisResult:
        length = len(password)
        unique_chars = len(set(password))
        uniqueness_ratio = (unique_chars / length) if length > 0 else 0.0

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        pool_entropy = cls.calculate_pool_entropy(password)
        shannon_entropy = cls.calculate_shannon_entropy(password)

        vulnerabilities = []
        recommendations = []
        score = 0

        # 1. Length Scoring (up to 35 points)
        if length == 0:
            vulnerabilities.append("Password is empty.")
            recommendations.append("Enter a password with at least 12 characters.")
        elif length < 8:
            score += length * 2
            vulnerabilities.append(f"Critically short length ({length} chars). Vulnerable to rapid brute-force.")
            recommendations.append("Increase password length to at least 12–16 characters.")
        elif length < 12:
            score += 20 + (length - 8) * 2
            vulnerabilities.append(f"Moderate length ({length} chars). NIST recommends 12+ characters.")
            recommendations.append("Add 4+ more characters or use a multi-word passphrase.")
        elif length < 16:
            score += 30
        else:
            score += 35

        # 2. Character Variety / Complexity (up to 30 points)
        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        if variety_count == 1 and length > 0:
            score += 5
            vulnerabilities.append("Uses only a single character class (severely restricts keyspace).")
        elif variety_count == 2:
            score += 15
        elif variety_count == 3:
            score += 22
        elif variety_count == 4:
            score += 30

        if not has_lower:
            recommendations.append("Include lowercase letters (a-z).")
        if not has_upper:
            recommendations.append("Include uppercase letters (A-Z).")
        if not has_digit:
            recommendations.append("Include numeric digits (0-9).")
        if not has_special:
            recommendations.append("Include special symbols (e.g., !@#$%^&*).")

        # 3. Uniqueness & Repetition (up to 15 points)
        if length > 0:
            if uniqueness_ratio < 0.5:
                vulnerabilities.append("High character repetition detected (low uniqueness ratio).")
                recommendations.append("Avoid repeating the same characters multiple times.")
                score += 3
            elif uniqueness_ratio < 0.75:
                score += 9
            else:
                score += 15

        # Check consecutive repeating characters (e.g., "aaa", "111")
        if re.search(r"(.)", password):
            vulnerabilities.append("Contains 3 or more identical consecutive characters (e.g., 'aaa' or '111').")
            recommendations.append("Break up repeated character runs.")
            score -= 10

        # 4. Entropy Bonus (up to 20 points)
        effective_entropy = min(pool_entropy, shannon_entropy * 1.8)
        if effective_entropy >= 80:
            score += 20
        elif effective_entropy >= 60:
            score += 15
        elif effective_entropy >= 45:
            score += 10
        elif effective_entropy >= 30:
            score += 5

        # 5. Pattern & Common Dictionary Checks (Penalties)
        clean_lower = re.sub(r"[^a-zA-Z0-9]", "", password).lower()
        if password.lower() in COMMON_PASSWORDS or clean_lower in COMMON_PASSWORDS:
            vulnerabilities.append("Matches a known top-breached dictionary password.")
            recommendations.append("Never use common words or predictable passwords like 'password123'.")
            score = min(score, 15)
            effective_entropy = min(effective_entropy, 12.0)

        if cls._detect_sequences(password):
            vulnerabilities.append("Contains predictable sequential or keyboard walk patterns (e.g., '123', 'abc', 'qwerty').")
            recommendations.append("Remove sequential keyboard or alphanumeric patterns.")
            score -= 15
            effective_entropy = max(10.0, effective_entropy - 15.0)

        # Year pattern check (19xx or 20xx)
        if re.search(r"(19\d\d|20\d\d)", password):
            vulnerabilities.append("Contains a calendar year pattern (19XX/20XX), which attackers prioritize in mask attacks.")
            recommendations.append("Avoid embedding birth years or current years.")
            score -= 8

        # Cap score for critically short passwords (< 8 characters)
        if length < 8:
            score = min(score, 30)

        # Clamp score between 0 and 100
        score = max(0, min(100, score))

        # Determine Rating
        if score < 25:
            rating = "Very Weak"
        elif score < 50:
            rating = "Weak"
        elif score < 70:
            rating = "Moderate"
        elif score < 85:
            rating = "Strong"
        else:
            rating = "Very Strong"

        if not recommendations and score >= 85:
            recommendations.append("Excellent password! Store it safely in a password manager and enable 2FA.")

        crack_time = cls.estimate_crack_time(effective_entropy)

        return AnalysisResult(
            password_length=length,
            unique_chars=unique_chars,
            uniqueness_ratio=uniqueness_ratio,
            has_lowercase=has_lower,
            has_uppercase=has_upper,
            has_digits=has_digit,
            has_special=has_special,
            pool_entropy_bits=pool_entropy,
            shannon_entropy_bits=shannon_entropy,
            score=score,
            rating=rating,
            estimated_crack_time=crack_time,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
        )
