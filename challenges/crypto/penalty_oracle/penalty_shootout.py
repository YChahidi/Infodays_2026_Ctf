import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

sys.stdout = open(sys.stdout.fileno(), 'w', buffering=1)

FLAG = os.environ.get('FLAG', 'infodays{test_flag_for_testing}').encode()

KEY = secrets.token_bytes(16)

SECRET_MESSAGE = FLAG

def encrypt():
    cipher = AES.new(KEY, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(SECRET_MESSAGE, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def decrypt_and_check_padding(iv_ciphertext):
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    if len(ciphertext) % 16 != 0:
        return False
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    try:
        decrypted = cipher.decrypt(ciphertext)
        unpad(decrypted, AES.block_size)
        return True
    except:
        return False

def main():
    encrypted_data = encrypt()
    
    sys.stdout.write("\n" + "🏆" * 20 + "\n")
    sys.stdout.write("⚽ FIFA WORLD CUP 2030 - MOROCCO 🇲🇦\n")
    sys.stdout.write("🏆" * 20 + "\n\n")
    
    sys.stdout.write("📋 MATCH SCHEDULE (ENCRYPTED):\n")
    sys.stdout.write(f"🔒 {encrypted_data.hex()}\n\n")
    
    sys.stdout.write("🟨 VAR (Video Assistant Referee) SYSTEM ONLINE 🟨\n")
    sys.stdout.write("⚡ The referee has hidden the match schedule.\n")
    sys.stdout.write("⚡ You can challenge VAR decisions by submitting your own ciphertext.\n\n")
    
    sys.stdout.write("📢 VAR RULES:\n")
    sys.stdout.write("   → Send your challenge as HEX (IV + Ciphertext)\n")
    sys.stdout.write("   → VAR will respond with: GOAL! (Valid) or OFFSIDE! (Invalid)\n")
    sys.stdout.write("   → Only perfect padding counts as a GOAL!\n\n")
    
    sys.stdout.write("🔮 ENTER YOUR CHALLENGE:\n")
    sys.stdout.write("> ")
    
    while True:
        try:
            line = sys.stdin.readline().strip()
            if not line:
                break
            user_input = bytes.fromhex(line)
            if len(user_input) < 32:
                sys.stdout.write("❌ TOO SHORT! Need at least 32 bytes (IV + ciphertext).\n")
                sys.stdout.write("> ")
                continue
            if decrypt_and_check_padding(user_input):
                sys.stdout.write("🥅 GOAL! 🎉 Valid padding. VAR CONFIRMS.\n")
            else:
                sys.stdout.write("🚩 OFFSIDE! ❌ Invalid padding. VAR OVERTURNS.\n")
            sys.stdout.write("> ")
        except:
            sys.stdout.write("⚠️ FOUL! Invalid hex format.\n")
            sys.stdout.write("> ")

if __name__ == "__main__":
    main()
