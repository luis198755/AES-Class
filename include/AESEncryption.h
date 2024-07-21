#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <Arduino.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

class AESEncryption {
public:
    AESEncryption();
    ~AESEncryption();

    String encrypt(const uint8_t* key, size_t keySize, const String& plaintext, String& nonce);
    String decrypt(const uint8_t* key, size_t keySize, const String& ciphertext, const String& nonce);

private:
    mbedtls_aes_context m_aesContext;
    mbedtls_entropy_context m_entropy;
    mbedtls_ctr_drbg_context m_ctrDrbg;

    static const size_t BLOCK_SIZE = 16;
    static const size_t NONCE_SIZE = 12;

    void initializeRNG();
    String bytesToHex(const uint8_t* bytes, size_t len);
    void hexToBytes(const String& hex, uint8_t* bytes, size_t len);
    void createInitialCounter(const uint8_t* nonce, uint32_t counter, uint8_t* initialCounter);
};

AESEncryption::AESEncryption() {
    mbedtls_aes_init(&m_aesContext);
    initializeRNG();
}

AESEncryption::~AESEncryption() {
    mbedtls_aes_free(&m_aesContext);
    mbedtls_ctr_drbg_free(&m_ctrDrbg);
    mbedtls_entropy_free(&m_entropy);
}

void AESEncryption::initializeRNG() {
    mbedtls_entropy_init(&m_entropy);
    mbedtls_ctr_drbg_init(&m_ctrDrbg);
    mbedtls_ctr_drbg_seed(&m_ctrDrbg, mbedtls_entropy_func, &m_entropy, nullptr, 0);
}

String AESEncryption::encrypt(const uint8_t* key, size_t keySize, const String& plaintext, String& nonce) {
    mbedtls_aes_setkey_enc(&m_aesContext, key, keySize * 8);

    uint8_t nonceBytes[NONCE_SIZE];
    mbedtls_ctr_drbg_random(&m_ctrDrbg, nonceBytes, NONCE_SIZE);
    nonce = bytesToHex(nonceBytes, NONCE_SIZE);

    size_t plaintextLength = plaintext.length();
    size_t ciphertextLength = plaintextLength;
    uint8_t* ciphertext = new uint8_t[ciphertextLength];

    uint8_t initialCounter[BLOCK_SIZE];
    createInitialCounter(nonceBytes, 1, initialCounter);

    uint8_t streamBlock[BLOCK_SIZE];
    size_t nc_off = 0;

    mbedtls_aes_crypt_ctr(&m_aesContext, plaintextLength, &nc_off, initialCounter, streamBlock, 
                          (const uint8_t*)plaintext.c_str(), ciphertext);

    String result = bytesToHex(ciphertext, ciphertextLength);
    delete[] ciphertext;

    return result;
}

String AESEncryption::decrypt(const uint8_t* key, size_t keySize, const String& ciphertext, const String& nonce) {
    mbedtls_aes_setkey_enc(&m_aesContext, key, keySize * 8);

    size_t ciphertextLength = ciphertext.length() / 2;  // Dos caracteres hex por byte
    uint8_t* ciphertextBytes = new uint8_t[ciphertextLength];
    hexToBytes(ciphertext, ciphertextBytes, ciphertextLength);

    uint8_t nonceBytes[NONCE_SIZE];
    hexToBytes(nonce, nonceBytes, NONCE_SIZE);

    uint8_t* plaintext = new uint8_t[ciphertextLength];

    uint8_t initialCounter[BLOCK_SIZE];
    createInitialCounter(nonceBytes, 1, initialCounter);

    uint8_t streamBlock[BLOCK_SIZE];
    size_t nc_off = 0;

    mbedtls_aes_crypt_ctr(&m_aesContext, ciphertextLength, &nc_off, initialCounter, streamBlock, 
                          ciphertextBytes, plaintext);

    String result((char*)plaintext, ciphertextLength);
    delete[] ciphertextBytes;
    delete[] plaintext;

    return result;
}

String AESEncryption::bytesToHex(const uint8_t* bytes, size_t len) {
    String result;
    for (size_t i = 0; i < len; i++) {
        char hex[3];
        sprintf(hex, "%02X", bytes[i]);
        result += hex;
    }
    return result;
}

void AESEncryption::hexToBytes(const String& hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex.c_str() + 2*i, "%2hhx", &bytes[i]);
    }
}

void AESEncryption::createInitialCounter(const uint8_t* nonce, uint32_t counter, uint8_t* initialCounter) {
    memcpy(initialCounter, nonce, NONCE_SIZE);
    initialCounter[12] = (counter >> 24) & 0xFF;
    initialCounter[13] = (counter >> 16) & 0xFF;
    initialCounter[14] = (counter >> 8) & 0xFF;
    initialCounter[15] = counter & 0xFF;
}

#endif // AES_ENCRYPTION_H