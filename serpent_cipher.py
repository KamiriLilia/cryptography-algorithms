#pip install pyserpent
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
import binascii

def text_to_key(key_text):
    """Convert user text to a 32-byte (256-bit) key"""
    # Encode to bytes and pad/truncate to 32 bytes
    key_bytes = key_text.encode('utf-8')
    if len(key_bytes) < 32:
        # Pad with zeros if too short
        key_bytes = key_bytes.ljust(32, b'\0')
    else:
        # Truncate if too long
        key_bytes = key_bytes[:32]
    return key_bytes

def hex_to_key(key_hex):
    """Convert hex string to 32-byte key"""
    try:
        key_bytes = binascii.unhexlify(key_hex)
        if len(key_bytes) != 32:
            print(f"⚠️ Warning: Key length is {len(key_bytes)} bytes (should be 32)")
            # Pad or truncate to 32 bytes
            if len(key_bytes) < 32:
                key_bytes = key_bytes.ljust(32, b'\0')
            else:
                key_bytes = key_bytes[:32]
        return key_bytes
    except:
        return None

def get_key_from_user():
    """Let user choose how to provide the key"""
    print("\n--- KEY INPUT ---")
    print("How would you like to provide the key?")
    print("1. Enter as text")
    print("2. Enter as hex (64 characters for 256-bit)")
    
    choice = input("Choice (1/2): ").strip()
    
    if choice == '1':
        key_text = input("Enter your key (any text): ").strip()
        if not key_text:
            print("❌ Key cannot be empty!")
            return None
        key = text_to_key(key_text)
        print(f"✓ Key set (length: {len(key)} bytes)")
        return key
    
    elif choice == '2':
        key_hex = input("Enter key in hex (64 hex chars for 256-bit): ").strip()
        key = hex_to_key(key_hex)
        if key is None:
            print("❌ Invalid hex format!")
            return None
        print(f"✓ Key set from hex (length: {len(key)} bytes)")
        return key
    
    else:
        print("❌ Invalid choice!")
        return None

def get_iv_from_user():
    """Let user provide IV or auto-generate"""
    print("\n--- IV INPUT ---")
    print("1. Enter IV as text (16 bytes)")
    print("2. Enter IV as hex (32 hex chars)")
    print("3. Auto-generate random IV")
    
    choice = input("Choice (1/2/3): ").strip()
    
    if choice == '1':
        iv_text = input("Enter IV text (16 characters): ").strip()
        iv_bytes = iv_text.encode('utf-8')
        if len(iv_bytes) < 16:
            iv_bytes = iv_bytes.ljust(16, b'\0')
        elif len(iv_bytes) > 16:
            iv_bytes = iv_bytes[:16]
        print(f"✓ IV set (length: {len(iv_bytes)} bytes)")
        return iv_bytes
    
    elif choice == '2':
        iv_hex = input("Enter IV in hex (32 hex chars): ").strip()
        try:
            iv_bytes = binascii.unhexlify(iv_hex)
            if len(iv_bytes) != 16:
                if len(iv_bytes) < 16:
                    iv_bytes = iv_bytes.ljust(16, b'\0')
                else:
                    iv_bytes = iv_bytes[:16]
            print(f"✓ IV set from hex")
            return iv_bytes
        except:
            print("❌ Invalid hex format! Using random IV instead.")
            return None
    
    elif choice == '3':
        print("✓ Using random IV")
        return None  # Will trigger auto-generation
    
    else:
        print("❌ Invalid choice! Using random IV.")
        return None

def encrypt_message():
    """Encrypt user-provided message with user-provided key"""
    print("\n" + "="*50)
    print("   ENCRYPTION MODE")
    print("="*50)
    
    # Get key from user
    key = get_key_from_user()
    if key is None:
        return
    
    # Get IV from user
    iv = get_iv_from_user()
    if iv is None:
        # Generate random IV
        import os
        iv = os.urandom(16)
        print(f"Auto-generated IV: {iv.hex()}")
    
    # Get plaintext
    plaintext = input("\nEnter the message to encrypt: ").strip()
    if not plaintext:
        print("❌ Message cannot be empty!")
        return
    
    try:
        # Encrypt
        encrypted = serpent_cbc_encrypt(key, plaintext, iv)
        
        print("\n" + "="*50)
        print("   ENCRYPTION RESULTS")
        print("="*50)
        print(f"Original message: {plaintext}")
        print(f"\nKey (hex): {key.hex()}")
        print(f"IV (hex): {iv.hex()}")
        print(f"\n🔒 Encrypted (hex): {encrypted.hex()}")
        print(f"🔒 Encrypted (bytes): {encrypted}")
        
        # Save option
        save = input("\nSave encrypted message to file? (y/n): ").strip().lower()
        if save == 'y':
            with open("encrypted_msg.bin", "wb") as f:
                f.write(encrypted)
            with open("encrypted_key_iv.txt", "w") as f:
                f.write(f"Key: {key.hex()}\nIV: {iv.hex()}")
            print("✓ Saved to 'encrypted_msg.bin' and 'encrypted_key_iv.txt'")
    
    except Exception as e:
        print(f"❌ Encryption failed: {e}")

def decrypt_message():
    """Decrypt message with user-provided key"""
    print("\n" + "="*50)
    print("   DECRYPTION MODE")
    print("="*50)
    
    # Get key from user
    key = get_key_from_user()
    if key is None:
        return
    
    # Get IV from user
    print("\n--- IV INPUT ---")
    iv_choice = input("Enter IV as hex (32 chars) or 'auto' to extract from file: ").strip()
    
    if iv_choice.lower() == 'auto':
        try:
            with open("encrypted_key_iv.txt", "r") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("IV:"):
                        iv_hex = line.split(":")[1].strip()
                        iv = binascii.unhexlify(iv_hex)
                        print(f"✓ IV loaded from file")
                        break
                else:
                    print("❌ Could not find IV in file")
                    return
        except:
            print("❌ Could not load IV from file")
            return
    else:
        try:
            iv = binascii.unhexlify(iv_choice)
            if len(iv) != 16:
                print(f"⚠️ IV length is {len(iv)} bytes, adjusting to 16")
                if len(iv) < 16:
                    iv = iv.ljust(16, b'\0')
                else:
                    iv = iv[:16]
        except:
            print("❌ Invalid hex format for IV!")
            return
    
    # Get ciphertext
    print("\n--- CIPHERTEXT INPUT ---")
    print("How would you like to provide the encrypted message?")
    print("1. Enter as hex")
    print("2. Load from file")
    
    choice = input("Choice (1/2): ").strip()
    
    encrypted = None
    
    if choice == '1':
        hex_input = input("Enter encrypted message (hex): ").strip()
        try:
            encrypted = binascii.unhexlify(hex_input)
            print(f"✓ Loaded {len(encrypted)} bytes from hex")
        except:
            print("❌ Invalid hex format!")
            return
    
    elif choice == '2':
        try:
            with open("encrypted_msg.bin", "rb") as f:
                encrypted = f.read()
            print(f"✓ Loaded {len(encrypted)} bytes from file")
        except:
            print("❌ Could not load file 'encrypted_msg.bin'")
            return
    
    else:
        print("❌ Invalid choice!")
        return
    
    try:
        # Decrypt
        decrypted = serpent_cbc_decrypt(key, encrypted)
        
        print("\n" + "="*50)
        print("   DECRYPTION RESULTS")
        print("="*50)
        print(f"🔓 Decrypted message: {decrypted.decode('utf-8')}")
        print(f"\nKey used (hex): {key.hex()}")
        print(f"IV used (hex): {iv.hex()}")
    
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        print("(This usually means the key, IV, or ciphertext is incorrect)")

def main():
    print("="*50)
    print("   SERPENT CIPHER - User Key Edition")
    print("="*50)
    print("\n⚠️  Important Notes:")
    print("   - You must remember the key and IV to decrypt!")
    print("   - Save both the encrypted message AND the key/IV")
    print("   - Keep the key secret!")
    
    while True:
        print("\n" + "-"*40)
        print("MAIN MENU")
        print("-"*40)
        print("1. 🔒 Encrypt a message")
        print("2. 🔓 Decrypt a message")
        print("3. ❌ Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            encrypt_message()
        
        elif choice == '2':
            decrypt_message()
        
        elif choice == '3':
            print("\nGoodbye! Keep your keys safe!")
            break
        
        else:
            print("❌ Invalid choice! Please enter 1, 2, or 3")

if __name__ == "__main__":
    main()