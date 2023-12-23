#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <vector>
#include <fstream>
#include <stdlib.h>
#include <iomanip>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "test.hpp"

extern "C"
{
#include <openssl/applink.c>
}

using namespace std;

int main() {
    const char publicKeyFile[] = "public.pem";
    const char privateKeyFile[] = "private.pem";
    char option;
    char choice;
    do
    {        
        cout << "(1) Encrypt using AES\n(2) Decrypt using AES\n(3) Sign using RSA\n(4) Veify using RSA\n(5) Sign + encrypt\n(6) Verify + decrypt\n";
        cin >> option;
        if (option == '1')
        {            
            option_1();
        }
        else if (option == '2')
        {                           
            option_2();
        }
        else if (option == '3')
        {                                              
            option_3();
        }
        else if (option == '4')
        {
            option_4();
        }
        else if (option == '5')
        {
            option_5();
        }
        else if (option == '6')
        {
            option_6();
        }
        else
        {
            cout << "Invalid input";
        }
        cout << endl << "Choose another operation(y/n)";
        cin >> choice;
    } while (choice == 'y' || choice == 'Y');
    return 0;
}



void encrypt(char* inFile, char* key)
{
    char command[1024];
    sprintf_s(command, "openssl enc -aes-256-cbc -salt -pbkdf2 -in %s -out file.enc -k %s", inFile, key);
    system(command);
    printf("\nEncryption is done");
}


void decrypt(char* inFile, char* key)
{
    char command[1024];
    sprintf_s(command, "openssl enc -aes-256-cbc -d -pbkdf2 -in %s -out file2.txt -k %s", inFile, key);
    system(command);
    printf("\nDecryption is done");
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


/* Function to sign data */
void signData(const unsigned char* plainText, unsigned int plainTextLen,
    const char* privateKeyFile, unsigned char* signature,
    size_t* signatureLen) {
    unsigned char hashValue[EVP_MAX_MD_SIZE];
    unsigned int hashSize;
    generateHash(plainText, plainTextLen, hashValue, &hashSize);
    signRSA(hashValue, hashSize, privateKeyFile, signature, signatureLen);    
    write_hex_file((char*)signature, *signatureLen);
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

    //if (EVP_PKEY_sign_init(ctx) <= 0 ||
    //    EVP_PKEY_sign(ctx, signature, signatureLen, data, dataLen) <= 0) {
    //    perror("Error during signing");
    //    exit(EXIT_FAILURE);
    //}

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




void write_hex_file(char* text, size_t size) {
    ofstream outputFile;
    outputFile.open("output.txt"); 
    if (outputFile)
    { 
        for (unsigned int i = 0; i < size; i++) { 
            outputFile << hex << setfill('0') << setw(2) << (int)text[i];
        }
        outputFile.close();
    }
    else
    {
        cout << "File could not be opened.\n"; 
    }
}


void writeFile(unsigned char* text, size_t size) {
  ofstream outputFile;
  outputFile.open("output.sigEnc"); 
  if (outputFile)
  { 
    for (unsigned int i = 0; i < size; i++) { 
      outputFile << text[i]; // write the char itself
    }
    outputFile.close();
  }
  else
  {
    cout << "File could not be opened.\n"; 
  }
}


void delete_file(char* file)
{
    char command[1024];
    sprintf_s(command, "rm %s",file);
    system(command);    
}


void print_hexa(char* text, unsigned int size)
{
    for (unsigned int i = 0; i < size; i++)
    {
        printf("%02x", text[i]);
    }
    printf("\n");
}


void print(char* text, unsigned int size)
{
    for (unsigned int i = 0; i < size; i++)
    {
        printf("%c", text[i]);
    }
    printf("\n");
}




bool readFile(string& content)
{
    string fileName;
    cout << "Enter the file name: ";
    cin >> fileName;

    ifstream inputFile;
    inputFile.open(fileName);

    if (!inputFile) {
        cerr << "Could not open the file.\n";
        return false;
    }

    string line;
    while (std::getline(inputFile, line)) {
        content += line + "\n";
    }

    inputFile.close();
    return true;
}

bool readFile(string fileName, string& content)
{    
    ifstream inputFile;
    inputFile.open(fileName);

    if (!inputFile) {
        cerr << "Could not open the file.\n";
        return false;
    }

    string line;
    while (std::getline(inputFile, line)) {
        content += line + "\n";
    }

    inputFile.close();
    return true;
}


void signPlain(char* inFile) {
    char command[1024];
    sprintf_s(command, "openssl pkeyutl -sign -in %s -out file.sig -inkey private.pem", inFile);
    system(command);
    cout << "Signature is done";    
}

void verifyPlain(char* inFile, char* sigFile) {
    char command[1024];
    sprintf_s(command, "openssl pkeyutl -verify -in %s -sigfile %s -pubin -inkey public.pem", inFile, sigFile);
    system(command);
    cout << "Signature is done";
}


void append_files(string file1, string file2) {
    // open the input files for reading
    ifstream in1(file1);
    ifstream in2(file2);
    // check if the input files are opened successfully
    if (!in1 || !in2) {
        cerr << "Error opening input files\n";
        return;
    }
    // open the output file for writing
    ofstream out("output.txt");
    // check if the output file is opened successfully
    if (!out) {
        cerr << "Error opening output file\n";
        return;
    }
    // copy the contents of the first input file to the output file
    out << in1.rdbuf();
    // copy the contents of the second input file to the output file
    out << in2.rdbuf();
    // close the files
    in1.close();
    in2.close();
    out.close();
}




void split_file(string file)
{
    ifstream in(file);
    if (!in) {
        cerr << "Error opening input file\n";
        return;
    }
    ofstream out1("temp1.txt");
    ofstream out2("temp2.txt");
    if (!out1 || !out2) {
        cerr << "Error opening output files\n";
        return;
    }
    char buffer[256];
    /* read the first 256 characters from the input file */
    in.read(buffer, 256);    
    out1.write(buffer, 256);
    /* copy the rest of the input file to the second output file */
    out2 << in.rdbuf();   
    in.close();
    out1.close();
    out2.close();
}








void option_1()
{
    string fileInString, keyString;
    size_t lenFileIn, lenFileOut, lenKey;
    cin >> fileInString >> keyString;
    lenFileIn = fileInString.size();
    lenKey = keyString.size();
    char* fileIn = new char[lenFileIn + 1];
    char* key = new char[lenKey + 1];
    strcpy_s(fileIn, lenFileIn + 1, fileInString.c_str());
    strcpy_s(key, lenKey + 1, keyString.c_str());
    encrypt(fileIn, key);
}

void option_2()
{
    string fileInString, keyString;
    int lenFileIn, lenFileOut, lenKey;
    cin >> fileInString >> keyString;
    lenFileIn = fileInString.size();
    lenKey = keyString.size();
    char* fileIn = new char[lenFileIn + 1];
    char* key = new char[lenKey + 1];
    strcpy_s(fileIn, lenFileIn + 1, fileInString.c_str());
    strcpy_s(key, lenKey + 1, keyString.c_str());
    decrypt(fileIn, key);
}

void option_3()
{
    string fileInString;
    cin >> fileInString;
    size_t fileInLen = fileInString.size();
    char* fileIn = new char[fileInLen + 1];
    strcpy_s(fileIn, fileInLen + 1, (const char*)fileInString.c_str());
    signPlain(fileIn);
}


void option_4()
{
    string plainFileStr;
    string sigFileStr;
    cin >> plainFileStr >> sigFileStr;
    size_t plainFileLen = plainFileStr.size();
    size_t sigFileLen = sigFileStr.size();
    char* plainFile = new char[plainFileLen + 1];
    char* sigFile = new char[sigFileLen + 1];
    strcpy_s(plainFile, plainFileLen + 1, (const char*)plainFileStr.c_str());
    strcpy_s(sigFile, sigFileLen + 1, (const char*)sigFileStr.c_str());
    verifyPlain(plainFile, sigFile);
}


void option_5()
{
    string fileInString, keyString;
    size_t lenFileIn, lenKey;
    cin >> fileInString >> keyString;
    lenFileIn = fileInString.size();
    lenKey = keyString.size();
    char* fileIn = new char[lenFileIn + 1];
    char* key = new char[lenKey + 1];
    strcpy_s(fileIn, lenFileIn + 1, fileInString.c_str());
    strcpy_s(key, lenKey + 1, keyString.c_str());
    encrypt(fileIn, key);
    cout << endl;
    signPlain(fileIn);
    /* append the two files in a third file and delete the first two */        
    /*append_files("file.sig", "file.enc");
    char sigFile[] = "file.sig";
    char encFile[] = "file.enc";*/
    //delete_file(sigFile);
    //delete_file(encFile);
}


void option_6()
{
    string encFileStr, sigFileStr, keyString;
    size_t lenFileIn, lenSigFile, lenKey;
    cin >> encFileStr >> sigFileStr >> keyString;
    lenFileIn = encFileStr.size();
    lenSigFile = sigFileStr.size();
    lenKey = keyString.size();    
    char* encFile = new char[lenFileIn + 1];    
    char* sigFile = new char[lenSigFile + 1];
    char* key = new char[lenKey + 1];
    strcpy_s(encFile, lenFileIn + 1, encFileStr.c_str());    
    strcpy_s(sigFile, lenSigFile + 1, sigFileStr.c_str());
    strcpy_s(key, lenKey + 1, keyString.c_str());        
    decrypt(encFile, key);
    cout << endl;
    char plain[] = "file2.txt";
    verifyPlain(plain, sigFile);
}