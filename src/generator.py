"""
Cryptographically Secure Password & Passphrase Suggestion Engine.
Uses Python's `secrets` module (CSPRNG) to generate high-entropy alternatives
and strengthen user-supplied weak passwords.
"""

import secrets
import string
from typing import List

SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

WORD_LIST = [
    "amber", "anchor", "apollo", "arctic", "atlas", "aurora", "avalanche", "bamboos",
    "baryon", "beacon", "bismuth", "blizzard", "bonsai", "breeze", "canyon", "carbon",
    "cascade", "catalyst", "celestial", "cipher", "citadel", "cobalt", "comet", "compass",
    "condor", "coral", "cosmos", "crimson", "crystal", "cyclone", "delta", "diamond",
    "dolphin", "dynamo", "eclipse", "emerald", "enigma", "equinox", "everest", "falcon",
    "fjord", "fortress", "fractal", "fusion", "galaxy", "garnet", "glacier", "granite",
    "gravity", "griffin", "harbor", "harmony", "helium", "horizon", "impulse", "indigo",
    "infinity", "isotope", "jasper", "javelin", "juniper", "krypton", "labyrinth", "lagoon",
    "lantern", "kinetic", "legend", "leopard", "liberty", "lightning", "lithium", "magnet",
    "mariner", "matrix", "meadow", "mercury", "meteor", "mirage", "monarch", "monolith",
    "monsoon", "mustang", "nebula", "nectar", "neptune", "neutron", "nexus", "nimbus",
    "nitrogen", "nomad", "nova", "obsidian", "odyssey", "olympus", "omega", "onyx",
    "orbit", "orchid", "orion", "osprey", "oxygen", "paladin", "panther", "paradox",
    "pegasus", "pendulum", "penguin", "phantom", "phoenix", "photon", "pioneer", "planet",
    "plasma", "platinum", "polaris", "polygon", "prism", "proton", "pulsar", "pyramid",
    "python", "quantum", "quartz", "quasar", "quicksilver", "radium", "raptor", "reactor",
    "redwood", "relativity", "resonance", "rhodium", "riptide", "rubicon", "sapphire", "saturn",
    "savanna", "scepter", "scorpion", "sequoia", "serenity", "shadow", "sierra", "silicon",
    "silver", "solstice", "sonata", "spectrum", "sphinx", "spiral", "spruce", "starlight",
    "stealth", "stellar", "stratos", "summit", "supernova", "symphony", "synapse", "talisman",
    "tangent", "tempest", "titanium", "topaz", "tornado", "torrent", "tracker", "trident",
    "trinity", "tsunami", "tungsten", "turbine", "twilight", "typhoon", "ultraviolet", "umbra",
    "unicorn", "uranium", "utopia", "valkyrie", "vanguard", "vector", "velocity", "velvet",
    "venture", "veridian", "vertex", "vibranium", "viking", "vintage", "violet", "viper",
    "voyager", "vortex", "vulcan", "wanderer", "warden", "whisper", "wildfire", "winter",
    "wolverine", "zenith", "zephyr", "zircon", "zodiac"
]

LEET_MAP = {
    "a": "@", "A": "4",
    "e": "3", "E": "3",
    "i": "!", "I": "1",
    "o": "0", "O": "0",
    "s": "$", "S": "$",
    "t": "+", "T": "7",
}


class PasswordGenerator:
    """Generates strong password alternatives using OS-level CSPRNG (`secrets`)."""

    @staticmethod
    def generate_random_password(length: int = 16) -> str:
        """Generates a high-entropy random password guaranteed to contain all 4 character classes."""
        length = max(12, length)
        alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + SYMBOLS

        # Guarantee at least two of each character class
        mandatory = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(string.digits),
            secrets.choice(SYMBOLS),
            secrets.choice(SYMBOLS),
        ]
        remaining = [secrets.choice(alphabet) for _ in range(length - len(mandatory))]
        combined = mandatory + remaining
        # Cryptographically shuffle using SystemRandom
        secrets.SystemRandom().shuffle(combined)
        return "".join(combined)

    @staticmethod
    def generate_passphrase(num_words: int = 4) -> str:
        """Generates a memorable Diceware-style high-entropy passphrase with symbols and digits."""
        num_words = max(3, num_words)
        chosen_words = [secrets.choice(WORD_LIST).capitalize() for _ in range(num_words)]
        sep = secrets.choice(["-", "_", ".", "!", "#"])
        random_num = secrets.randbelow(900) + 100
        return f"{sep.join(chosen_words)}{sep}{random_num}"

    @staticmethod
    def strengthen_user_password(base_password: str, target_length: int = 16) -> str:
        """
        Takes a user's weak password and transforms it into a significantly stronger variant
        by mixing case, injecting cryptographic noise, and padding to target length.
        """
        if not base_password:
            return PasswordGenerator.generate_random_password(target_length)

        # Strip common trailing digits like '123'
        cleaned = base_password.strip()
        transformed = []
        for idx, ch in enumerate(cleaned):
            if ch in LEET_MAP and secrets.randbelow(2) == 0:
                transformed.append(LEET_MAP[ch])
            elif ch.isalpha():
                transformed.append(ch.upper() if idx % 2 == 0 else ch.lower())
            else:
                transformed.append(ch)

        core = "".join(transformed)
        prefix = secrets.choice(SYMBOLS) + secrets.choice(string.ascii_uppercase)
        suffix = secrets.choice(SYMBOLS) + str(secrets.randbelow(90) + 10) + secrets.choice(WORD_LIST).capitalize()

        candidate = f"{prefix}{core}{suffix}"
        while len(candidate) < target_length:
            candidate += secrets.choice(string.ascii_letters + string.digits + SYMBOLS)

        return candidate

    @classmethod
    def suggest_alternatives(cls, current_password: str = "") -> List[dict]:
        """Returns 3 diverse strong password suggestions with descriptions."""
        suggestions = [
            {
                "type": "Enhanced Variant (Based on Input)",
                "password": cls.strengthen_user_password(current_password, 16),
                "description": "Strengthens your input with random salts, symbols, and case variation."
            },
            {
                "type": "Memorable Cryptographic Passphrase",
                "password": cls.generate_passphrase(4),
                "description": "High-entropy multi-word passphrase—easy for humans to remember, hard for GPUs to crack."
            },
            {
                "type": "Maximum-Security CSPRNG Random (18 chars)",
                "password": cls.generate_random_password(18),
                "description": "Pure cryptographically random characters generated via OS entropy (`secrets`)."
            }
        ]
        return suggestions
