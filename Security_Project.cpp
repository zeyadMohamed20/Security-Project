#define _CRT_SECURE_NO_DEPRECATE
#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <vector>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>

using namespace std;

#define BUFSIZE 1024

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext);

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext);

int generateHash(const unsigned char* plain_text, unsigned int plain_text_length,
    unsigned char* hash, unsigned int* hash_length);

void append(const unsigned char* text1, const unsigned char* text2, unsigned char* result);

int main()
{
    /******************************** For Encryption/Decryption **********************************/
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

    /**************************** For Hasing *******************************************************/
    // A sample plain text
    unsigned char plainText[] = "hello";
    unsigned int plainSize = sizeof(plainText) - 1;

    // Generate hash value for the plain text using SHA512
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashSize;
    bool status = generateHash(plainText, plainSize, hashValue, &hashSize);

    if (status)
    {
        unsigned int resultSize = plainSize + hashSize;
        unsigned char* result = new unsigned char[resultSize];
        
        // Call the append function
        append(plainText, hashValue, result);

        /*Display Hash Value*/
        printf("Hash: ");
        for (unsigned int i = 0; i < hashSize; i++) {
            printf("%02x", hashValue[i]);
        }
        printf("\n");

        /*Display plain text + hash value after appending*/
        cout << "Plain + Hash: ";
        for (unsigned int i = 0; i < resultSize; i++) {
            printf("%02x", result[i]);
        }
        cout << endl;
    }
    /************************************************************************************************/

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

// A function that uses SHA512 in OpenSSL and prints the hash value of the plain text
int generateHash(const unsigned char* plain_text, unsigned int plain_text_length,
    unsigned char* hash, unsigned int* hash_length)
{
    // Create a new EVP_MD context for the SHA512 algorithm
    const EVP_MD* md = EVP_sha512();
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    // Check if context creation was successful
    if (!ctx) {
        printf("Error creating EVP_MD context\n");
        return false;
    }

    // Initialize the context with the SHA512 algorithm
    if (EVP_DigestInit(ctx, md) != 1) {
        printf("Error initializing EVP_MD context\n");

        // Clean up and destroy the context in case of an error
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    // Update the hash context with the input plain_text
    EVP_DigestUpdate(ctx, plain_text, plain_text_length);

    // Finalize the hash computation and retrieve the digest
    if (EVP_DigestFinal(ctx, hash, hash_length) != 1) {
        printf("Error finalizing hash\n");

        // Clean up and destroy the context in case of an error
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    // Clean up and destroy the context
    EVP_MD_CTX_destroy(ctx);

    // Return true to indicate successful hash generation
    return true;
}

void append(const unsigned char* text1, const unsigned char* text2, unsigned char* result)
{
    // Determine the lengths of the strings
    size_t len1 = strlen(reinterpret_cast<const char*>(text1));
    size_t len2 = strlen(reinterpret_cast<const char*>(text2));

    // Copy the first string into the result array
    strcpy(reinterpret_cast<char*>(result), reinterpret_cast<const char*>(text1));

    // Concatenate the second string to the result array
    strcat(reinterpret_cast<char*>(result), reinterpret_cast<const char*>(text2));
}

