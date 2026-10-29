#!/usr/bin/env python3
"""
Decrypt an AES-256-GCM, Base64-encoded 'data' string from the IRCTC API.

You now know: algorithm = AES-256-GCM, encoding = Base64, IV random per response.
Still required: the 32-byte SECRET KEY from the provider.

Setup:
    pip install pycryptodome

Usage:
    1. Put the secret key into SECRET_KEY below (see KEY NOTES).
    2. python3 decrypt_gcm.py
"""

import base64
import binascii
import json

from Crypto.Cipher import AES  # pip install pycryptodome


# ---- FILL THIS IN ----------------------------------------------------------
# KEY NOTES: AES-256 needs a key that is exactly 32 BYTES.
# The provider gives it in one of these forms — pick the matching line:
SECRET_KEY = "PASTE_SECRET_KEY_HERE"   # how the provider gave it to you
KEY_FORMAT = "utf8"   # "utf8"  -> a 32-character text string
                      # "hex"   -> a 64-character hex string
                      # "base64"-> a Base64 string that decodes to 32 bytes

# If the IV is sent in a RESPONSE HEADER instead of inside the data string,
# paste it here (otherwise leave as None and the script finds it in the data).
IV_FROM_HEADER = None          # e.g. "a1b2c3..."
IV_HEADER_FORMAT = "hex"       # "hex" or "base64"

DATA = (
    "SNVBmeVikAIvI/WA4t4IUc9+ITbNr9JnQw7ER8KiO2m5W0wkiaiEFhTDxsEQPiQnJcktZgcJr7VK2h4VksgPcNOB7BmX+1lu1T7TvrI7uixTBFP/hStXxcK0npdKjBcDosz6c+AaMZTbSK/STH1Ftvuh7OGhLthfNhrFkkm95RLlxKqN69DrIU68xXHXT9RQNuXjFDb0g85XXXAFi6riXwUuGDsggGxjknhYk/L43m6HhrEBwLqykOUG5TTXr1yo75N7SB9O+1FXMntQTu2Cd+uor8ShzEVjs1eSrzgA3SNUiasI5DbMXO2AU/JIm+UsBYF/D5HA9KlJGJIQjgHQrtDGGJ+DAYtOGbd5vOpLgu1mAAUsvdstvg6X4kd1x23Dn32/Rlw1oIi/nrO++eE1FwCCHu8Eo9wYDaBtQ/AhRyPArMwW3oAPfa4ubYv5lkg9IylKPwb0E/W8BegQK3dSN188p8oo6C1hda9Ru6sewu6U6OlhrkVhHT1r+JbrRViCGPtTDbAkdh1VToQNuM4Ojm/YcRlx0UAwUtEnM64YRgOB16BOo6bE1fJ25NLZJH01b8K5M6kq05QSoL3EJOyI/YO6so/nNaPJNlZGPgiGWuiQI5RY9ur8e6EU3hqbcMpcVEsPoTIXzgVHlFvQ4dnTwlAVFV9tVunm+Bvk755qwelDOkevC9SlrsMy7COeBhx4R3edTN5XGbuneXykbyjab34KXtQq4pEEuVk="
)
# ---------------------------------------------------------------------------


def load_key():
    if KEY_FORMAT == "utf8":
        k = SECRET_KEY.encode("utf-8")
    elif KEY_FORMAT == "hex":
        k = binascii.unhexlify(SECRET_KEY)
    elif KEY_FORMAT == "base64":
        k = base64.b64decode(SECRET_KEY)
    else:
        raise ValueError("KEY_FORMAT must be utf8, hex, or base64")
    if len(k) != 32:
        raise ValueError(
            f"Key is {len(k)} bytes, but AES-256 needs exactly 32. "
            f"Check KEY_FORMAT or the key itself."
        )
    return k


def pretty(pt):
    s = pt.decode("utf-8")
    return json.dumps(json.loads(s), indent=2, ensure_ascii=False)


def main():
    if SECRET_KEY == "PASTE_SECRET_KEY_HERE":
        print("ERROR: Put the 32-byte secret key into SECRET_KEY first.")
        return

    key = load_key()
    blob = base64.b64decode(DATA)
    print(f"Key: {len(key)} bytes OK | Payload: {len(blob)} bytes\n")

    attempts = []

    if IV_FROM_HEADER:
        iv = (binascii.unhexlify(IV_FROM_HEADER)
              if IV_HEADER_FORMAT == "hex"
              else base64.b64decode(IV_FROM_HEADER))
        # IV in header -> data is ciphertext + tag(16)
        attempts.append(("IV from header, tag last 16", iv, blob[:-16], blob[-16:]))
    else:
        # IV embedded in the data string. Try the two standard layouts.
        # Layout A: iv(12) + ciphertext + tag(16)   <- most common for GCM
        attempts.append(("iv first 12 + ct + tag last 16",
                         blob[:12], blob[12:-16], blob[-16:]))
        # Layout B: iv(16) + ciphertext + tag(16)
        attempts.append(("iv first 16 + ct + tag last 16",
                         blob[:16], blob[16:-16], blob[-16:]))
        # Layout C: ciphertext + tag(16) + iv(12) at the end
        attempts.append(("ct + tag(16) + iv last 12",
                         blob[-12:], blob[:-28], blob[-28:-12]))

    for name, iv, ct, tag in attempts:
        try:
            pt = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
            print("=" * 60)
            print("SUCCESS:", name)
            print("-" * 60)
            print(pretty(pt))
            return
        except Exception as e:
            print(f"  tried [{name}] -> no ({type(e).__name__})")

    print("\nNone worked. If the key is definitely correct, then the IV/tag")
    print("layout is non-standard — ask the provider exactly how IV and tag")
    print("are positioned in the payload, or whether the IV is in a header.")


if __name__ == "__main__":
    main()
