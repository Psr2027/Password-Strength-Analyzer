#!/usr/bin/env python3
"""
Password Strength Analyzer - Interactive CLI & Command-Line Tool.
Run `python main.py` for interactive menu or `python main.py --password "MyPass"` for quick check.
"""

import argparse
import sys
from src.analyzer import PasswordAnalyzer
from src.generator import PasswordGenerator
from src.database import PasswordHistoryDB


def print_banner():
    print("=" * 72)
    print("   🔐 PASSWORD STRENGTH ANALYZER & CRYPTOGRAPHIC HISTORY GUARD 🔐")
    print("=" * 72)


def display_analysis(password: str, result):
    bar_filled = int(result.score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print("
" + "-" * 72)
    print(f"Target Password      : {password}")
    print(f"Strength Score       : [{bar}] {result.score}/100 ({result.rating})")
    print(f"Length & Uniqueness  : {result.password_length} chars ({result.unique_chars} unique, {int(result.uniqueness_ratio * 100)}% uniqueness)")
    print(
        f"Character Classes    : "
        f"Lower[{'✓' if result.has_lowercase else '✗'}]  "
        f"Upper[{'✓' if result.has_uppercase else '✗'}]  "
        f"Digits[{'✓' if result.has_digits else '✗'}]  "
        f"Symbols[{'✓' if result.has_special else '✗'}]"
    )
    print(f"Pool Entropy         : {result.pool_entropy_bits:.2f} bits")
    print(f"Shannon Entropy      : {result.shannon_entropy_bits:.2f} bits")
    print(f"Est. Offline Crack   : {result.estimated_crack_time} (@ 10B guesses/sec)")
    print("-" * 72)

    if result.vulnerabilities:
        print("
⚠️  Identified Vulnerabilities:")
        for v in result.vulnerabilities:
            print(f"   • {v}")

    if result.recommendations:
        print("
💡 Actionable Recommendations:")
        for r in result.recommendations:
            print(f"   • {r}")

    if result.score < 85:
        print("
🛡️  Suggested Stronger Alternatives:")
        for s in PasswordGenerator.suggest_alternatives(password):
            print(f"   [{s['type']}]")
            print(f"   👉 {s['password']}")
            print(f"      ({s['description']})")
    print("-" * 72)


def interactive_mode(db_path: str):
    print_banner()
    db = PasswordHistoryDB(db_path)

    while True:
        print("
Select an option:")
        print("  [1] Analyze a Password & Get Stronger Alternatives")
        print("  [2] Register / Update User Password (with Reuse Prevention DB)")
        print("  [3] View User Cryptographic Password Audit History")
        print("  [4] Generate Standalone High-Entropy Passwords")
        print("  [5] Exit")

        choice = input("
Enter choice (1-5): ").strip()

        if choice == "1":
            pw = input("Enter password to evaluate: ")
            res = PasswordAnalyzer.analyze(pw)
            display_analysis(pw, res)

        elif choice == "2":
            username = input("Enter username (e.g., alice): ").strip()
            pw = input("Enter new password: ")
            res = PasswordAnalyzer.analyze(pw)
            display_analysis(pw, res)

            success, msg = db.store_password(username, pw, res.pool_entropy_bits, res.score)
            status_icon = "✅" if success else "❌"
            print(f"
{status_icon} Database Policy Result: {msg}")

        elif choice == "3":
            username = input("Enter username to inspect audit log: ").strip()
            logs = db.get_user_audit_log(username)
            if not logs:
                print(f"
No password history found for user '{username}'.")
            else:
                print(f"
📜 Salted PBKDF2-HMAC-SHA256 History for '{username}':")
                print(f"{'ID':<5} {'Salt (Hex)':<16} {'PBKDF2 Hash':<22} {'Entropy':<12} {'Score':<8} {'Timestamp (UTC)'}")
                print("-" * 88)
                for row in logs:
                    print(
                        f"{row['id']:<5} {row['salt_preview']:<16} {row['hash_preview']:<22} "
                        f"{row['entropy_bits']:<12} {row['score']:<8} {row['created_at']}"
                    )

        elif choice == "4":
            print("
🔑 Generated Cryptographically Secure Passwords:")
            for item in PasswordGenerator.suggest_alternatives(""):
                print(f"  • {item['type']}: {item['password']}")

        elif choice == "5":
            print("Exiting Password Strength Analyzer. Stay secure!")
            break
        else:
            print("Invalid option. Please choose 1–5.")


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer & Cryptographic Reuse Prevention Tool"
    )
    parser.add_argument("-p", "--password", type=str, help="Evaluate a single password via CLI")
    parser.add_argument("-u", "--user", type=str, help="Username to check/save password against SQLite history DB")
    parser.add_argument("--db", type=str, default="password_history.db", help="Path to SQLite database file")
    args = parser.parse_args()

    if args.password is not None:
        res = PasswordAnalyzer.analyze(args.password)
        display_analysis(args.password, res)
        if args.user:
            db = PasswordHistoryDB(args.db)
            success, msg = db.store_password(args.user, args.password, res.pool_entropy_bits, res.score)
            print(f"
{'✅' if success else '❌'} {msg}")
            sys.exit(0 if success else 1)
    else:
        interactive_mode(args.db)


if __name__ == "__main__":
    main()
