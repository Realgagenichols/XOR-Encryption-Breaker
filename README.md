# XOR Encryption Program

This program provides functionalities for XOR encryption and decryption. It allows you to encrypt text or files as well as break XOR encryption when the key is unknown.

## Features

- Encryption: Encrypts text or files using XOR encryption with a given key.
- Key Breaker: Attempts to break XOR encryption by trying different keys and selecting the one that produces the most English-like decrypted text.

## Requirements

- Python 3

## Usage

To run the program, use the following command:

```shell
python xor_cipher.py <mode> <input_data> [<key>]
```

- `<mode>`: The mode of operation. Available modes are `encrypt` and `break`.
- `<input_data>`: The input text or file to be encrypted or broken.
- `<key>` (optional): The encryption or decryption key.

### Examples

Encrypting a text file:

```shell
python xor_cipher.py encrypt plaintext.txt mykey
```

Breaking XOR encryption:

```shell
python xor_cipher.py break encrypted.bin
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

