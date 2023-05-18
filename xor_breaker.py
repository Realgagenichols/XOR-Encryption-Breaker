import sys
import string
import os

# Expected letter frequencies in English language
expected_frequencies = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.0236, 'x': 0.0015, 'y': 0.01974, 'z': 0.00074
}

def xor_encrypt(plaintext, key):
    encrypted = bytearray()
    key_length = len(key)
    for i in range(len(plaintext)):
        key_byte = ord(str(key[i % key_length]))  # Convert key character to ASCII value
        encrypted_byte = plaintext[i] ^ key_byte
        encrypted.append(encrypted_byte)
    return encrypted


def xor_decrypt(ciphertext, key):
    decrypted = bytearray()
    for i in range(len(ciphertext)):
        decrypted.append(ciphertext[i] ^ key)
    return decrypted

def calculate_letter_frequencies(text):
    frequencies = {}
    total_letters = 0

    for char in text:
        if char.isalpha():
            char = char.lower()
            frequencies[char] = frequencies.get(char, 0) + 1
            total_letters += 1

    for char in frequencies:
        frequencies[char] /= total_letters

    return frequencies

def calculate_frequency_score(frequencies):
    score = 0
    for char in frequencies:
        expected_freq = expected_frequencies.get(char, 0)
        observed_freq = frequencies[char]
        score += abs(observed_freq - expected_freq)
    return score

def break_xor_encryption(ciphertext):
    best_score = float('inf')
    best_key = None
    best_decrypted_text = None

    for i in range(256):
        key = i
        try:
            decrypted_text = xor_decrypt(ciphertext, key)

            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'windows-1252']
            for encoding in encodings:
                try:
                    decrypted_text = decrypted_text.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue

            letter_frequencies = calculate_letter_frequencies(decrypted_text)
            score = calculate_frequency_score(letter_frequencies)

            if score < best_score:
                best_score = score
                best_key = chr(key)
                best_decrypted_text = decrypted_text

        except UnicodeDecodeError:
            continue

    if best_key is not None:
        print("Possible key found:", best_key)
        print("Decrypted text:")
        print(best_decrypted_text)



def xor_encrypt_mode(input_data, key):
    try:
        with open(input_data, "rb") as file:
            plaintext = file.read().encode()
        base_name = os.path.splitext(input_data)[0]  # Extract base name without extension
    except FileNotFoundError:
        plaintext = input_data.encode()
        base_name = os.path.splitext(input_data.strip())[0]  # Strip whitespace and extract base name

    base_name = base_name.replace(" ", "_")  # Replace spaces with underscores

    output_file_path = f"{base_name}.encrypted"
    count = 1
    while os.path.exists(output_file_path):
        output_file_path = f"{base_name}-{count}.encrypted"
        count += 1

    encrypted_text = xor_encrypt(plaintext, key)
    with open(output_file_path, "wb") as output_file:
        output_file.write(encrypted_text)

    print("Encryption completed. Encrypted file saved as:", output_file_path)




def xor_break_mode(input_data):
    try:
        with open(input_data, "rb") as file:
            ciphertext = file.read()
            break_xor_encryption(ciphertext)
    except FileNotFoundError:
        print("File not found:", input_data)

def main():
    if len(sys.argv) < 3:
        print("Usage: python xor_cipher.py <mode> <input_data> [<key>]")
        print("Modes: encrypt, break")
        return

    mode = sys.argv[1]
    input_data = sys.argv[2]

    if mode == "encrypt":
        if len(sys.argv) < 4:
            print("Usage: python xor_cipher.py encrypt <input_data> <key>")
            return
        key = sys.argv[3]
        xor_encrypt_mode(input_data, key)
    elif mode == "break":
        xor_break_mode(input_data)
    else:
        print("Invalid mode. Available modes: encrypt, break")


if __name__ == "__main__":
    main()

