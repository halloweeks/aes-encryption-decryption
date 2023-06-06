# AES-256 CBC Encryption and Decryption

This repository contains a C++ implementation of AES-256 CBC encryption and decryption using the OpenSSL library. The program provides a command-line interface for easy usage and supports input from file and output to file.

## Features

- AES-256 CBC encryption

- AES-256 CBC decryption

- Input from file

- Output to file

- Command-line interface for easy usage

## Prerequisites

To build and run this project, you need to have the following:

- C++ compiler

- OpenSSL library (version 1.1.0 or higher)

## Installation

1. Clone the repository:

```bash

git clone https://github.com/halloweeks/aes-encryption-decryption.git

```

2. Build the project using your preferred C++ compiler. Make sure to link against the OpenSSL library.

```bash

cd aes-encryption-decryption

g++ main.cpp -lssl -lcrypto -o aes

```

## Usage

The program accepts the following command-line arguments:

```bash

./aes input.file output.file -d or -e

```

- `input.file`: Path to the input file to be encrypted or decrypted.

- `output.file`: Path to the output file where the result will be written.

- `-d` or `-e`: Specify `-d` for decryption or `-e` for encryption.

Example:

```bash

./aes plaintext.txt ciphertext.bin -e

```

The above command will encrypt the `plaintext.txt` file using AES-256 CBC and write the resulting ciphertext to `ciphertext.bin`.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- The implementation is based on the OpenSSL library.

- The AES-256 CBC encryption and decryption algorithms are used.


