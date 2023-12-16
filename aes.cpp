#include <string>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>

#define BUFSIZE 1024

void encrypt(unsigned char* plaintext, unsigned char* key,
    unsigned char* ciphertext);

void decrypt(unsigned char* ciphertext, unsigned char* key,
    unsigned char* plaintext);

int main()
{
    unsigned char plaintext[] = "BishoyOmar";
    unsigned char ciphertext[BUFSIZE];
    unsigned char key[] = "00ff11ff45fffff";  // 128-bit key
    unsigned char decryptedtext[BUFSIZE];

    /* Encryption */
    encrypt(plaintext, key, ciphertext);

    /* Decryption */
    decrypt(ciphertext, key, decryptedtext);

    /* Print Cipher */
    int ciphertext_len = strlen((char*)ciphertext);
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    /* Print Decrypted text */
    printf("Decrypted text: %s\n", decryptedtext);
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