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
#include <openssl/sha.h>

#pragma warning(disable : 4996)


#define BUFSIZE 1024



int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext);

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext);

unsigned char* generateHash(const unsigned char* plain_text, size_t length);



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





// A function that uses SHA512 in open ssl and prints the hash value of the plain text
unsigned char* generateHash(const unsigned char* plain_text, size_t length) {
    // Create a SHA512_CTX object to store the context of the hashing operation
    SHA512_CTX ctx;
    // Initialize the context
    SHA512_Init(&ctx);
    // Update the context with the plain text data and its length
    SHA512_Update(&ctx, plain_text, length);
    // Create a buffer to store the output hash
    unsigned char hash[SHA512_DIGEST_LENGTH];
    // Finalize the context and store the hash in the buffer
    SHA512_Final(hash, &ctx);
    
    // Print the hash in hexadecimal format
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return hash;
}


///* Append the plain text with the generated hash value from SHA512 */
//void append()
//{
//
//}





int main()
{
    //unsigned char plaintext[] = "Hello, OpenSSL!";
    //unsigned char ciphertext[BUFSIZE];
    //unsigned char key[] = "0123456789abcdef";  // 128-bit key
    //unsigned char iv[] = "0123456789abcdef";   // 128-bit IV

    //int plaintext_len = strlen((char*)plaintext);
    //int ciphertext_len;

    ///* Encryption */
    //ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);
    //printf("Ciphertext: ");
    //for (int i = 0; i < ciphertext_len; i++) {
    //    printf("%02x", ciphertext[i]);
    //}
    //printf("\n");

    ///* Decryption */
    //unsigned char decryptedtext[BUFSIZE];
    //int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    //decryptedtext[decryptedtext_len] = '\0';  // Null-terminate the decrypted text
    //printf("Decrypted text: %s\n", decryptedtext);

    /* Sign */
    // A sample plain text
    unsigned char plain_text[] = "Hello World!";
    // Call the sign function with the plain text and its length
    unsigned char* hash = generateHash(plain_text, sizeof(plain_text) - 1);
    //append(plain_text, )
}