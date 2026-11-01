"""Create one hashed SocrAItes user record for LESMAAT_USERS_JSON."""

import getpass
import hashlib
import json
import secrets
import sys
from pathlib import Path


username = (sys.argv[1] if len(sys.argv) > 1 else input("Gebruikersnaam: ")).strip()
if not username:
    raise SystemExit("Gebruikersnaam ontbreekt.")
password = getpass.getpass("Wachtwoord: ")
if not password:
    raise SystemExit("Wachtwoord ontbreekt.")
salt = secrets.token_bytes(16)
password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
record = {username: {"salt": salt.hex(), "hash": password_hash.hex()}}
local_path = Path(__file__).with_name("users.local.json")
existing = {}
if local_path.exists():
    try:
        loaded = json.loads(local_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            existing = loaded
    except (json.JSONDecodeError, OSError):
        pass
existing.update(record)
local_path.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(record, ensure_ascii=False))
print(f"Opgeslagen in {local_path}")
