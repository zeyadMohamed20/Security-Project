#pragma once

#define BUFSIZE                    4096

using namespace std;

void encrypt(char* inFile, char* key_str);
void decrypt(char* inFile, char* key_str);
int generateHash(const unsigned char* plain_text, unsigned int plain_text_length, unsigned char* hash, unsigned int* hash_length);
int encryptRSA(unsigned char* data, int dataLen, const char* keyFile, unsigned char* ciphertext);
int decryptRSA(unsigned char* data, int dataLen, const char* KeyFile, unsigned char* decryptedtext);
void sign(unsigned char* plainText, unsigned int plainTextLen, const char* privateKeyFile, unsigned char* cipherHash, unsigned int* CipherHashSize);
void print_hexa(char* text, unsigned int size);
void print(char* text, unsigned int size);
bool verifyRSASignature(const unsigned char* data, unsigned int dataLen, const char* publicKeyFile, const unsigned char* signature, size_t* signatureLen);
void signRSA(const unsigned char* data, unsigned int dataLen, const char* privateKeyFile, unsigned char* signature, size_t* signatureLen);
void verifySignature(const unsigned char* plainText, unsigned int plainTextLen, const char* publicKeyFile, const unsigned char* signature, size_t* signatureLen);
void signData(const unsigned char* plainText, unsigned int plainTextLen, const char* privateKeyFile, unsigned char* signature, size_t* signatureLen);
void generate_key(void);
void getKey(unsigned char* key, int size);
bool readFile(string& content);
bool readFile(string fileName, string& content);
void write_hex_file(char* text, size_t size);
void writeFile(unsigned char* text, size_t size);
void signPlain(char* inFile);
void verifyPlain(char* inFile, char* sigFile);
void append(const unsigned char* text1, const unsigned char* text2, unsigned char* result);
void append_files(string file1, string file2);
void delete_file(char* file);
void split_file(string file);
void option_1();
void option_2();
void option_3();
void option_4();
void option_5();
void option_6();