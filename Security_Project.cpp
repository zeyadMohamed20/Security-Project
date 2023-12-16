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

#pragma warning(disable : 4996)

#define BUFSIZE 1024

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
void generateHash(const unsigned char* plain_text, size_t length, unsigned char*);
void append(unsigned char* plainText, unsigned int plainSize, unsigned char* encryptedHash);
int encryptRSA(unsigned char* data, int dataLen, const char* keyFile, unsigned char* ciphertext);
int decryptRSA(unsigned char* data, int dataLen, const char* KeyFile, unsigned char* decryptedtext);
void hash_asym_sym(unsigned char* plainText, unsigned int plainTextLen, unsigned char* hashValue, const char* privateKeyFile, unsigned char* ciphertext);

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
void generateHash(const unsigned char* plain_text, size_t length, 
                            unsigned char* hash)
{
    // Create a SHA512_CTX object to store the context of the hashing operation
    SHA512_CTX ctx;
    // Initialize the context
    SHA512_Init(&ctx);
    // Update the context with the plain text data and its length
    SHA512_Update(&ctx, plain_text, length);

    // Finalize the context and store the hash in the buffer
    SHA512_Final(hash, &ctx);
    
    // Print the hash in hexadecimal format
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}


/* Append the plain text with the generated hash value from SHA512 */
void append(unsigned char* plainText, unsigned int plainSize, 
            unsigned char* encryptedHash)
{
    // Print the plainText
    for (unsigned int i = 0; i < plainSize; i++) {
        printf("%c", plainText[i]);
    }
    // Print the encrypted hash value
    for (unsigned int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", encryptedHash[i]);
    }
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
   2- Encrypt it in RSA using private key
   3- Append it with the plain text 
*/
void hash_asym_sym(unsigned char* plainText, unsigned int plainTextLen,
                   unsigned char* hashValue, const char* privateKeyFile,
                   unsigned char* ciphertext)
{
    /* Generate hash value for the plain text using SHA512 */
    generateHash(plainText, plainTextLen, hashValue);

    /* Encrypt the hash using the private key */ 
    encryptRSA(hashValue, SHA512_DIGEST_LENGTH * 2, privateKeyFile, ciphertext);

    /* Append the plainText with the encrypted hash value (This is the data sent) */
    append(plainText, plainTextLen, hashValue);
}



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


    unsigned char plainText[] = "hello";
    unsigned int plainTextLen = sizeof(plainText) - 1;
    unsigned char ciphertext[BUFSIZE];

    // Paths to your public and private key files
    const char* publicKeyFile = "public.pem";
    const char* privateKeyFile = "private.pem";
    unsigned char hashValue[SHA512_DIGEST_LENGTH];

    hash_asym_sym(plainText, plainTextLen, hashValue, privateKeyFile, ciphertext);

}