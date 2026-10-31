"""
Cryptographic Password History Database Manager.
Prevents reuse of old passwords using SQLite and PBKDF2-HMAC-SHA256 salted hashes.
Plaintext passwords are NEVER stored on disk.
"""

import hashlib
import hmac
import os
import sqlite3
from datetime import datetime, timezone
from typing import Tuple, List, Dict


class PasswordHistoryDB:
    """
    Manages user password history using salted PBKDF2-HMAC-SHA256 key derivation
    to prevent password reuse while protecting stored credentials.
    """

    ITERATIONS = 200_000
    HASH_NAME = "sha256"
    SALT_BYTES = 16

    def __init__(self, db_path: str = "password_history.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    salt_hex TEXT NOT NULL,
                    password_hash_hex TEXT NOT NULL,
                    entropy_bits REAL NOT NULL,
                    score INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_username ON password_history (username)"
            )
            conn.commit()

    @classmethod
    def hash_password(cls, password: str, salt: bytes = None) -> Tuple[str, str]:
        """
        Derives a cryptographic hash using PBKDF2-HMAC-SHA256 with 200,000 iterations.
        Returns (salt_hex, hash_hex).
        """
        if salt is None:
            salt = os.urandom(cls.SALT_BYTES)
        derived = hashlib.pbkdf2_hmac(
            cls.HASH_NAME,
            password.encode("utf-8"),
            salt,
            cls.ITERATIONS
        )
        return salt.hex(), derived.hex()

    @classmethod
    def verify_password(cls, password: str, salt_hex: str, stored_hash_hex: str) -> bool:
        """
        Verifies a candidate password against a stored salt and hash using
        constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.
        """
        salt = bytes.fromhex(salt_hex)
        _, candidate_hash_hex = cls.hash_password(password, salt)
        return hmac.compare_digest(candidate_hash_hex, stored_hash_hex)

    def is_password_reused(self, username: str, candidate_password: str) -> Tuple[bool, str]:
        """
        Checks if the user has ever used `candidate_password` previously.
        Returns (is_reused: bool, timestamp_if_reused: str).
        """
        username = username.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT salt_hex, password_hash_hex, created_at FROM password_history WHERE username = ? ORDER BY id DESC",
                (username,)
            )
            rows = cursor.fetchall()

        for salt_hex, stored_hash_hex, created_at in rows:
            if self.verify_password(candidate_password, salt_hex, stored_hash_hex):
                return True, created_at
        return False, ""

    def store_password(
        self,
        username: str,
        password: str,
        entropy_bits: float,
        score: int,
        min_required_score: int = 50
    ) -> Tuple[bool, str]:
        """
        Validates that the password meets minimum security threshold and has not been
        used before by `username`, then stores its salted PBKDF2 hash.
        """
        username = username.strip().lower()
        if not username:
            return False, "Username cannot be empty."

        if score < min_required_score:
            return (
                False,
                f"Password rejected: Score ({score}/100) is below minimum policy threshold ({min_required_score}/100)."
            )

        reused, used_date = self.is_password_reused(username, password)
        if reused:
            return (
                False,
                f"Password reuse prevented! This password was already used by '{username}' on {used_date}."
            )

        salt_hex, hash_hex = self.hash_password(password)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO password_history (username, salt_hex, password_hash_hex, entropy_bits, score, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, salt_hex, hash_hex, round(entropy_bits, 2), score, timestamp)
            )
            conn.commit()

        return True, f"Password securely salted, hashed (PBKDF2-HMAC-SHA256), and saved for '{username}'."

    def get_user_audit_log(self, username: str) -> List[Dict[str, str]]:
        """Returns non-sensitive metadata of historical password updates for a user."""
        username = username.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, salt_hex, substr(password_hash_hex, 1, 16) || '...', entropy_bits, score, created_at
                FROM password_history
                WHERE username = ?
                ORDER BY id DESC
                """,
                (username,)
            )
            rows = cursor.fetchall()

        return [
            {
                "id": r[0],
                "salt_preview": r[1][:12] + "...",
                "hash_preview": r[2],
                "entropy_bits": r[3],
                "score": r[4],
                "created_at": r[5]
            }
            for r in rows
        ]
