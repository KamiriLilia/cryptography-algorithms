def caesar_cipher(text, shift, direction):
    result = ""

    # Adjust shift for direction
    if direction.lower() == "left":
        shift = shift
    elif direction.lower() == "right":
        shift = -shift
    else:
        print("Invalid direction. Use 'left' or 'right'.")
        return None

    for char in text:
        if char.isalpha():
            # Preserve case
            base = ord('A') if char.isupper() else ord('a')
            # Shift within alphabet
            new_char = chr((ord(char) - base + shift) % 26 + base)
            result += new_char
        else:
            # Keep non-letters unchanged
            result += char

    return result


def main():
    print("Caesar Cipher Program")
    print("1. Encrypt")
    print("2. Decrypt")

    choice = input("Choose option (1/2): ")

    if choice not in ["1", "2"]:
        print("Invalid choice.")
        return

    text = input("Enter your message: ")
    direction = input("Shift direction (left/right): ").lower()

    try:
        shift = int(input("Enter shift amount (number): "))
    except ValueError:
        print("Shift must be a number.")
        return

    # For decryption, reverse shift
    if choice == "2":
        shift = -shift

    result = caesar_cipher(text, shift, direction)

    if result is not None:
        if choice == "1":
            print("Encrypted message:", result)
        else:
            print("Decrypted message:", result)


if __name__ == "__main__":
    main()