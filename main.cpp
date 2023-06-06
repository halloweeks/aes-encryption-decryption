#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include "aes.hpp"

static const size_t KEY_SIZE = 256 / 8;
static const size_t BLOCK_SIZE = 128 / 8;
static const size_t CHUNK_SIZE = 1024 * 16;

void test_encrypt(const uint8_t *key, const char* in, const char* out) {
	// Initialization Vector (IV) for encryption
	uint8_t iv[BLOCK_SIZE];
	
	// Buffer to hold chunks of data read from the input file
	uint8_t chunk[CHUNK_SIZE];
	
	// Temporary buffer for encrypted data
	uint8_t temp[CHUNK_SIZE + BLOCK_SIZE];
	
	// Length variable, input and output file descriptors
	int len, fin, fout;
	
	// Open the input file in read-only mode and assign the file descriptor to 'fin'
	fin = open(in, O_RDONLY);
	
	// Open the output file with write, create, and truncate flags, and assign the file descriptor to 'fout'
	fout = open(out, O_WRONLY | O_CREAT | O_TRUNC, 644);
	
	// Generate random IV (Initialization Vector)
	RAND_bytes(iv, sizeof(iv));
	
	// Create an AES encryption object 'aes' with the provided encryption key 'key' and initialization vector 'iv'
	Encrypt aes(key, iv);
	
	// Write IV to the output file
	write(fout, &iv, sizeof(iv));
	
	// Read data from the input file into the 'chunk' buffer until the end of file is reached
	while ((len = read(fin, chunk, CHUNK_SIZE)) > 0) {
		// Perform encryption on the data in the 'chunk' buffer using the AES encryption object 'aes'
		// The encrypted data is stored in the 'temp' buffer, and the length of the encrypted data is assigned to 'len'
		len = aes.update(chunk, len, temp);
		// Write the encrypted data from the 'temp' buffer to the output file descriptor 'fout'
		write(fout, temp, len);
    }
    
    // Perform the final encryption operation and store the encrypted data in the 'temp' buffer
    // The length of the final encrypted data is assigned to 'len'
    len = aes.final(temp);
    
    // Write the final encrypted data from the 'temp' buffer to the output file descriptor 'fout'
    write(fout, temp, len);
    
    // Close the input and output file descriptors
    close(fin);
    close(fout);
}

void test_decrypt(const uint8_t *key, const char* in, const char* out) {
	// Initialization Vector (IV) for decryption
	uint8_t iv[BLOCK_SIZE];
	
	// Buffer to hold chunks of data read from the input file
	uint8_t chunk[CHUNK_SIZE];
	
	// Temporary buffer for decryption data
	uint8_t temp[CHUNK_SIZE + BLOCK_SIZE];
	
	// Length variable, input and output file descriptors
	int len, fin, fout;
	
	// Read the Initialization Vector (IV) from the input file descriptor 'fin' into the 'iv' buffer
	read(fin, iv, sizeof(iv));
	
	// Open the input file in read-only mode and assign the file descriptor to 'fin'
	fin = open(in, O_RDONLY);
	
	// Open the output file with write, create, and truncate flags, and assign the file descriptor to 'fout'
	fout = open(out, O_WRONLY | O_CREAT | O_TRUNC, 644);
	
	// Create an AES decryption object 'aes' with the provided decryption key 'key' and initialization vector 'iv'
	Decrypt aes(key, iv);
	
	// Read data from the input file into the 'chunk' buffer until the end of file is reached
	while ((len = read(fin, chunk, CHUNK_SIZE)) > 0) {
		// Perform decryption on the data in the 'chunk' buffer using the AES decryption object 'aes'
		// The decrypted data is stored in the 'temp' buffer, and the length of the decrypted data is assigned to 'len'
		len = aes.update(chunk, len, temp);
		// Write the decrypted data from the 'temp' buffer to the output file descriptor 'fout'
		write(fout, temp, len);
	}
	
	// Perform the final decryption operation and store the decrypted data in the 'temp' buffer
    // The length of the final decrypted data is assigned to 'len'
    len = aes.final(temp);
    
    // Write the final decrypted data from the 'temp' buffer to the output file descriptor 'fout'
    write(fout, temp, len);
    
    // Close the input and output file descriptors
    close(fin);
    close(fout);
}

// Entry point of the program, accepts command-line arguments
int main(int argc, char* argv[]) {
	// Check if the number of command-line arguments is not equal to 4
	if (argc != 4) {
		printf("Usage ./aes input.file output.file -d or -e\n");
		return -1;
	}
	
	// Declare variables to hold the start and end times for measuring execution duration
	clock_t start, end;
	
	// Capture the current clock ticks as the start time for measuring execution duration
	start = clock();
	
	// Load error strings for OpenSSL cryptographic library
	ERR_load_crypto_strings();
	
	// Initialize OpenSSL library and add all available cryptographic algorithms
	OpenSSL_add_all_algorithms();
	
	// Configure OpenSSL library using default configuration
	// OPENSSL_config(NULL);
	
	// Define a 256-bit (32-byte) AES encryption decryption key
	uint8_t key[KEY_SIZE] = {
        0x24, 0x43, 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E,
        0x63, 0x52, 0x66, 0x54, 0x6A, 0x57, 0x6E, 0x5A,
        0x72, 0x34, 0x75, 0x37, 0x78, 0x21, 0x41, 0x25,
        0x44, 0x2A, 0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64
    };
	
	// Check if the input file exists
	if (access(argv[1], F_OK) != 0) {
		printf("Input file %s not found\n", argv[1]);
		return -1;
	}
	
	// Check the command-line option for encryption or decryption
	if (strcmp(argv[3], "-e") == 0) {
		// Perform encryption
		test_encrypt(key, argv[1], argv[2]);
	} else if (strcmp(argv[3], "-d") == 0) {
		// Perform decryption
		test_decrypt(key, argv[1], argv[2]);
	} else {
		// Invalid option
		printf("Invalid option\n");
		return -1;
	}
	
	// Capture the current clock ticks as the end time for measuring execution duration
	end = clock();
	
	// Calculate the time taken for the process to complete
	double time_taken = (double)(end - start) / (double)(CLOCKS_PER_SEC);
	
	// Display the execution duration in seconds
	printf("[TIME] PROCESS COMPLETE IN %f\n", time_taken);
	
	// Return 0 to indicate successful execution
	return 0;
}