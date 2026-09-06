# Black Bulls — Captain's mana signature service config
# Internal use only. Do NOT commit changes without Captain Yami's approval.

CAPTAIN_SECRET = "__REPLACE_ME__"
MANA_CHANNEL = "dark-slash-cleaving"

def verify_captain(signature: str) -> bool:
    # used by captain.py internal service to gate the root vault
    return signature == CAPTAIN_SECRET
