#ifndef AES_256_CBC
#define AES_256_CBC 1

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

class AESBase {
protected:
    const uint8_t *key, *iv;
    EVP_CIPHER_CTX *ctx;
    AESBase(const uint8_t *key, const uint8_t *iv) : key(key), iv(iv) {
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();
    }
    ~AESBase() {
        EVP_CIPHER_CTX_free(ctx);
    }
    static void handleErrors(void) {
        ERR_print_errors_fp(stderr);
        abort();
    }
};

class Encrypt : AESBase {
public:
    Encrypt(const uint8_t *key, const uint8_t *iv) : AESBase(key, iv) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }
    int update(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
        int len;
        if (1 != EVP_EncryptUpdate(ctx, (uint8_t*)ciphertext, &len, (const uint8_t*)plaintext, plaintext_len))
            handleErrors();
        return len;
    }
    int final(unsigned char *ciphertext) {
        int len;
        if (1 != EVP_EncryptFinal_ex(ctx, (uint8_t*)ciphertext, &len))
            handleErrors();
        return len;
    }
};

class Decrypt : AESBase {
public:
    Decrypt(const uint8_t *key, const uint8_t *iv) : AESBase(key, iv) {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }
    int update(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
        int len;
        if (1 != EVP_DecryptUpdate(ctx, (uint8_t*)plaintext, &len, (const uint8_t*)ciphertext, ciphertext_len))
            handleErrors();
        return len;
    }
    int final(unsigned char *plaintext) {
        int len;
        if (1 != EVP_DecryptFinal_ex(ctx, (uint8_t*)plaintext, &len))
            handleErrors();
        return len;
    }
};

#endif