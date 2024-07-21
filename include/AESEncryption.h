#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <Arduino.h>
#include <mbedtls/aes.h>

class AESEncryption {
public:
    AESEncryption(const uint8_t* key, size_t keySize);
    ~AESEncryption();

    bool encrypt(const uint8_t* input, size_t inputLength, uint8_t* output, size_t* outputLength);
    bool decrypt(const uint8_t* input, size_t inputLength, uint8_t* output, size_t* outputLength);
    
    void encryptAndDecrypt(const char* message);

private:
    mbedtls_aes_context m_aesContext;
    uint8_t m_key[32];  // Soporte para claves de hasta 256 bits
    size_t m_keySize;

    static const size_t BLOCK_SIZE = 16;  // Tamaño de bloque AES en bytes
};

AESEncryption::AESEncryption(const uint8_t* key, size_t keySize) : m_keySize(keySize) {
    if (keySize > sizeof(m_key)) {
        m_keySize = sizeof(m_key);
    }
    memcpy(m_key, key, m_keySize);
    mbedtls_aes_init(&m_aesContext);
    mbedtls_aes_setkey_enc(&m_aesContext, m_key, m_keySize * 8);
}

AESEncryption::~AESEncryption() {
    mbedtls_aes_free(&m_aesContext);
    memset(m_key, 0, sizeof(m_key));
}

bool AESEncryption::encrypt(const uint8_t* input, size_t inputLength, uint8_t* output, size_t* outputLength) {
    size_t blocks = (inputLength + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (*outputLength < blocks * BLOCK_SIZE) {
        return false;
    }

    for (size_t i = 0; i < blocks; i++) {
        if (mbedtls_aes_crypt_ecb(&m_aesContext, MBEDTLS_AES_ENCRYPT, 
                                  input + i * BLOCK_SIZE, 
                                  output + i * BLOCK_SIZE) != 0) {
            return false;
        }
    }

    *outputLength = blocks * BLOCK_SIZE;
    return true;
}

bool AESEncryption::decrypt(const uint8_t* input, size_t inputLength, uint8_t* output, size_t* outputLength) {
    if (inputLength % BLOCK_SIZE != 0 || *outputLength < inputLength) {
        return false;
    }

    size_t blocks = inputLength / BLOCK_SIZE;

    for (size_t i = 0; i < blocks; i++) {
        if (mbedtls_aes_crypt_ecb(&m_aesContext, MBEDTLS_AES_DECRYPT, 
                                  input + i * BLOCK_SIZE, 
                                  output + i * BLOCK_SIZE) != 0) {
            return false;
        }
    }

    *outputLength = inputLength;
    return true;
}

void AESEncryption::encryptAndDecrypt(const char* message) {
    size_t messageLength = strlen(message);
    size_t paddedLength = ((messageLength + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    
    uint8_t* plaintext = new uint8_t[paddedLength];
    uint8_t* ciphertext = new uint8_t[paddedLength];
    uint8_t* decrypted = new uint8_t[paddedLength];
    
    memset(plaintext, 0, paddedLength);
    memcpy(plaintext, message, messageLength);

    size_t outputLength = paddedLength;

    Serial.println("Mensaje original: " + String(message));

    if (encrypt(plaintext, paddedLength, ciphertext, &outputLength)) {
        Serial.print("Texto cifrado: ");
        for (size_t i = 0; i < outputLength; i++) {
            Serial.printf("%02X", ciphertext[i]);
        }
        Serial.println();

        outputLength = paddedLength;
        if (decrypt(ciphertext, paddedLength, decrypted, &outputLength)) {
            Serial.print("Mensaje descifrado: ");
            Serial.println((char*)decrypted);
        } else {
            Serial.println("Falló el descifrado");
        }
    } else {
        Serial.println("Falló el cifrado");
    }

    delete[] plaintext;
    delete[] ciphertext;
    delete[] decrypted;
}

#endif // AES_ENCRYPTION_H