#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstring>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>

#define BUFSIZE 1024

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext);

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext);

int main()
{
    unsigned char plaintext[] = "Hello, OpenSSL!";
    unsigned char ciphertext[BUFSIZE];
    unsigned char key[] = "0123456789abcdef";  // 128-bit key
    unsigned char iv[] = "0123456789abcdef";   // 128-bit IV

    int plaintext_len = strlen((char*)plaintext);
    int ciphertext_len;

    /* Encryption */
    ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    /* Decryption */
    unsigned char decryptedtext[BUFSIZE];
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';  // Null-terminate the decrypted text
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}

/* Function to encrypt data */
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;
    int len;

    int ciphertext_len;

    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialize the cipher for encryption */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    /* Provide the plaintext to be encrypted */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    ciphertext_len = len;

    /* Finalize the encryption */
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* Function to decrypt data */
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;
    int len;

    int plaintext_len;

    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialize the cipher for decryption */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    /* Provide the ciphertext to be decrypted */
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    /* Finalize the decryption */
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}