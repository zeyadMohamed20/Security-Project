#define _CRT_SECURE_NO_DEPRECATE
#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <vector>
#include <fstream>
#include <stdlib.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

extern "C"
{
#include <openssl/applink.c>
}

using namespace std;

#define BUFSIZE 1024

void encrypt(unsigned char* plaintext, unsigned char* key, unsigned char* ciphertext);
void decrypt(unsigned char* ciphertext, unsigned char* key, unsigned char* plaintext);
int generateHash(const unsigned char* plain_text, unsigned int plain_text_length, unsigned char* hash, unsigned int* hash_length);
void append(const unsigned char* text1, const unsigned char* text2, unsigned char* result);
int encryptRSA(unsigned char* data, int dataLen, const char* keyFile, unsigned char* ciphertext);
int decryptRSA(unsigned char* data, int dataLen, const char* KeyFile, unsigned char* decryptedtext);
void hash_asym_sym(unsigned char* plainText, unsigned int plainTextLen, const char* privateKeyFile, unsigned char* result);
void sign(unsigned char* plainText, unsigned int plainTextLen, const char* privateKeyFile, unsigned char* cipherHash, unsigned int* CipherHashSize);
void print(unsigned char* text, unsigned int size);
bool verifyRSASignature(const unsigned char* data, unsigned int dataLen, const char* publicKeyFile, const unsigned char* signature, size_t* signatureLen);
void signRSA(const unsigned char* data, unsigned int dataLen, const char* privateKeyFile, unsigned char* signature, size_t* signatureLen);
void verifySignature(const unsigned char* plainText, unsigned int plainTextLen, const char* publicKeyFile, const unsigned char* signature, size_t* signatureLen);
void signData(const unsigned char* plainText, unsigned int plainTextLen, const char* privateKeyFile, unsigned char* signature, size_t* signatureLen);
unsigned char* get_string();
void generate_key(void);
void getKey(unsigned char* key, int size);

int main() {
    const char* publicKeyFile = "public.pem";
    const char* privateKeyFile = "private.pem";
    unsigned char* plaintext;
    plaintext = get_string();
    char option;
    char choice;
    do
    {
        printf("(1) Encrypt/Decrypt using AES128\n(2) Sign/Veify using RSA\n(3) Sign + encrypt/verify + decrypt\n");
        cin >> option;
        if (option == '1')
        {
            unsigned char cipherText[4096];
            unsigned char decryptedText[sizeof(plaintext)];
            unsigned char key[16];    /* AES key size = 16Bytes */
            getKey(key, sizeof(key));
            /* Encryption */
            encrypt(plaintext, key, cipherText);
            int ciphertextLen = strlen((char*)cipherText);
            print(cipherText, ciphertextLen);
            /* Decryption */
            decrypt(cipherText, key, decryptedText);
            printf("Decrypted text: %s\n", decryptedText);
        }
        else if (option == '2')
        {
            /* sign/verify */
            generate_key();
            unsigned char signature[4096];  // Adjust the size based on your key size
            size_t signatureLen;

            /* Sign the data */
            signData(plaintext, strlen((const char*)plaintext), privateKeyFile, signature, &signatureLen);
            
            /* Verify the signature */
            verifySignature(plaintext, strlen((const char*)plaintext), publicKeyFile, signature, &signatureLen);
        }
        else if (option == '3')
        {
            unsigned char signature[256];  // Adjust the size based on your key size
            unsigned char sigCipher[4096];
            unsigned char key[16];    /* AES key size = 16Bytes */
            unsigned char decryptedSig[256];
            size_t signatureLen;
            unsigned int plainTextLen = strlen((const char*)plaintext);

            generate_key();
            /* sign */
            signData(plaintext, plainTextLen, privateKeyFile, signature, &signatureLen);
            printf("Signaure: ");
            print(signature, signatureLen);
            getKey(key, sizeof(key));
            /* encrypt */
            encrypt(signature, key, sigCipher);
            printf("encrypted hash: %x", sigCipher);
            /* decrypt */
            decrypt(sigCipher, key, decryptedSig);
            /* verify */
            verifySignature(decryptedSig, plainTextLen, publicKeyFile, decryptedSig, &signatureLen);
        }
        else
        {
            printf("Invalid input");
        }
        printf("\nChoose another operation(y/n)");
        cin >> choice;
    } while (choice == 'y' || choice == 'Y');
    return 0;
}


/* Function to encrypt data */
void encrypt(unsigned char* plaintext, unsigned char* key,
    unsigned char* ciphertext)
{
    int plaintext_len = strlen((char*)plaintext);

    EVP_CIPHER_CTX* ctx;
    int len;

    int ciphertext_len;

    unsigned char iv[] = "\0";

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

    ciphertext[ciphertext_len] = '\0';
}

/* Function to decrypt data */
void decrypt(unsigned char* ciphertext, unsigned char* key,
    unsigned char* plaintext)
{
    int ciphertext_len = strlen((char*)ciphertext);

    EVP_CIPHER_CTX* ctx;
    int len;

    int plaintext_len;

    unsigned char iv[] = "\0";

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

    plaintext[plaintext_len] = '\0';  // Null-terminate the decrypted text
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
    size_t len1 = strlen((const char*)text1);
    size_t len2 = strlen((const char*)text2);

    // Copy the first string into the result array
    strcpy((char*)result, (const char*)text1);

    // Concatenate the second string to the result array
    strcat((char*)result, (const char*)text2);
}

/* Function to encrypt data using RSA */
/* Function to encrypt data using RSA */
int encryptRSA(unsigned char* plaintext, int plaintext_len, const char* publicKeyFile, unsigned char* ciphertext)
{
    size_t rsa_ciphertext_len;
    FILE* publicKey;
    fopen_s(&publicKey, publicKeyFile, "rb");
    if (!publicKey) {
        perror("Error opening public key file");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* evp_key = PEM_read_PUBKEY(publicKey, NULL, NULL, NULL);
    if (!evp_key) {
        perror("Error reading public key");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (!ctx) {
        perror("Error creating context");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_encrypt(ctx, ciphertext, &rsa_ciphertext_len, plaintext, plaintext_len) <= 0) {
        perror("Error during encryption");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
    fclose(publicKey);

    return rsa_ciphertext_len;
}

/* Function to decrypt data using RSA */
int decryptRSA(unsigned char* ciphertext, int ciphertext_len, const char* privateKeyFile, unsigned char* decryptedtext)
{
    FILE* privateKey;
    fopen_s(&privateKey, privateKeyFile, "rb");
    if (!privateKey) {
        perror("Error opening private key file");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* evp_key = PEM_read_PrivateKey(privateKey, NULL, NULL, NULL);
    if (!evp_key) {
        perror("Error reading private key");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (!ctx) {
        perror("Error creating context");
        exit(EXIT_FAILURE);
    }

    size_t decryptedtext_len = 0;
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_decrypt(ctx, NULL, &decryptedtext_len, ciphertext, ciphertext_len) <= 0) {
        perror("Error during decryption (getting buffer size)");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_decrypt(ctx, decryptedtext, &decryptedtext_len, ciphertext, ciphertext_len) <= 0) {
        perror("Error during decryption");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
    fclose(privateKey);

    // Null-terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    return decryptedtext_len;
}


/*
   1- Generate hash value for the plain text using SHA512
   2- Encrypt hash in RSA using private key
   Both steps 1 and 2 are Sign stage
   3- Encrypt plain using AES (Encryption)
   4- Append encrypted hash with encrypted plain
*/
void hash_asym_sym(unsigned char* plainText, unsigned int plainTextLen,
    const char* privateKeyFile, unsigned char* result)
{
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashSize;

    /* Generate hash value for the plain text using SHA512 */
    generateHash(plainText, plainTextLen, hashValue, &hashSize);

    unsigned char* cipherHash = new unsigned char[hashSize];
    unsigned char* cipherText = new unsigned char[plainTextLen];

    /* Encrypt Plain Text Using AES*/

    /* Encrypt the hash using the private key */
    encryptRSA(hashValue, hashSize, privateKeyFile, cipherHash);

    /* Append the encrypted plainText with the encrypted hash value (This is the data sent) */
    append(cipherText, cipherHash, result);

    delete[]cipherHash;
    delete[]cipherText;
}

/*
* 1- Generate hash value for the plain text using SHA512
  2- Encrypt hash in RSA using private key
*/
void sign(unsigned char* plainText, unsigned int plainTextLen,
    const char* privateKeyFile, unsigned char* cipherHash, unsigned int* CipherHashSize)
{
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashSize;


    /* Generate hash value for the plain text using SHA512 */
    generateHash(plainText, plainTextLen, hashValue, &hashSize);

    *CipherHashSize = hashSize;
    cipherHash = new unsigned char[*CipherHashSize];

    /* Encrypt the hash using the private key */
    encryptRSA(hashValue, hashSize, privateKeyFile, cipherHash);

}

void print(unsigned char* text, unsigned int size)
{
    for (unsigned int i = 0; i < size; i++)
    {
        printf("%02x", text[i]);
    }
    printf("\n");
}
/* Function to sign data */
void signData(const unsigned char* plainText, unsigned int plainTextLen,
    const char* privateKeyFile, unsigned char* signature,
    size_t* signatureLen) {
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashSize;

    /* Generate hash value for the plain text using SHA512 */
    generateHash(plainText, plainTextLen, hashValue, &hashSize);

    /* Sign the hash using the private key */
    signRSA(hashValue, hashSize, privateKeyFile, signature, signatureLen);
    printf("Signature created successfully.\n");
}

/* Function to verify the signature */
void verifySignature(const unsigned char* plainText, unsigned int plainTextLen,
    const char* publicKeyFile, const unsigned char* signature,
    size_t* signatureLen) {
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashSize;

    /* Generate hash value for the plain text using SHA512 */
    generateHash(plainText, plainTextLen, hashValue, &hashSize);

    /* Verify the signature using the public key */
    bool verificationResult = verifyRSASignature(hashValue, hashSize, publicKeyFile, signature, signatureLen);
    /* Print the verification result */
    if (verificationResult) {
        printf("\nSignature verified successfully.\n");
    }
    else {
        printf("\nSignature verification failed.\n");
    }
}

/* Function to sign data using RSA */
void signRSA(const unsigned char* data, unsigned int dataLen,
    const char* privateKeyFile, unsigned char* signature,
    size_t* signatureLen) {
    FILE* privateKey;
    fopen_s(&privateKey, privateKeyFile, "rb");
    if (!privateKey) {
        perror("Error opening private key file");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* evp_key = PEM_read_PrivateKey(privateKey, NULL, NULL, NULL);
    if (!evp_key) {
        perror("Error reading private key");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (!ctx) {
        perror("Error creating context");
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_sign(ctx, signature, signatureLen, data, dataLen) <= 0) {
        perror("Error during signing");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
    fclose(privateKey);
}

/* Function to verify the signature using RSA */
bool verifyRSASignature(const unsigned char* data, unsigned int dataLen,
    const char* publicKeyFile, const unsigned char* signature,
    size_t* signatureLen) {
    FILE* publicKey;
    fopen_s(&publicKey, publicKeyFile, "rb");
    if (!publicKey) {
        perror("Error opening public key file");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* evp_key = PEM_read_PUBKEY(publicKey, NULL, NULL, NULL);
    if (!evp_key) {
        perror("Error reading public key");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (!ctx) {
        perror("Error creating context");
        exit(EXIT_FAILURE);
    }

    int result = EVP_PKEY_verify_init(ctx);
    if (result <= 0) {
        perror("Error initializing verification context");
        exit(EXIT_FAILURE);
    }

    result = EVP_PKEY_verify(ctx, signature, *signatureLen, data, dataLen);
    if (result < 0) {
        perror("Error during verification");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
    fclose(publicKey);

    return result == 1; // 1 indicates successful verification, 0 or negative values indicate failure
}


unsigned char* get_string() {
    char buffer[BUFSIZ];
    printf("Enter a string: ");
    fgets(buffer, 100, stdin);
    size_t len = sizeof(buffer) - 1;
    unsigned char* array = new unsigned char[len];
    if (array == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    memcpy(array, buffer, len);
    return array;
}

void generate_key(void)
{
    /* generate RSA 2 keys in file private.pem and publiv.pem*/
    const char* key = "openssl genpkey -algorithm RSA -out private.pem";
    int result = system(key);
    const char* keyGen = "openssl rsa -pubout -in private.pem -out public.pem";
    result = system(keyGen);
}

void getKey(unsigned char* key, int size)
{
    cout << "Enter the shared key (16 char): ";
    for (int i = 0; i < size; i++)
    {
        cin >> key[i];
    }
}