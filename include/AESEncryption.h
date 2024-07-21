#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <Arduino.h>
#include <mbedtls/aes.h>

class AESEncryption {
public:
    AESEncryption(const uint8_t* key, size_t keySize);
    ~AESEncryption();

    bool encrypt(const uint8_t* nonce, size_t nonceSize, uint32_t counter,
                 const uint8_t* input, size_t inputLength, 
                 uint8_t* output, size_t* outputLength);

    bool decrypt(const uint8_t* nonce, size_t nonceSize, uint32_t counter,
                 const uint8_t* input, size_t inputLength, 
                 uint8_t* output, size_t* outputLength);
    
    void encryptAndDecrypt(const char* message);

private:
    mbedtls_aes_context m_aesContext;
    uint8_t m_key[32];  // Soporte para claves de hasta 256 bits
    size_t m_keySize;

    static const size_t BLOCK_SIZE = 16;  // Tamaño de bloque AES en bytes

    bool ctrOperation(const uint8_t* nonce, size_t nonceSize, uint32_t counter,
                      const uint8_t* input, size_t inputLength, 
                      uint8_t* output, size_t* outputLength);
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

bool AESEncryption::ctrOperation(const uint8_t* nonce, size_t nonceSize, uint32_t counter,
                                 const uint8_t* input, size_t inputLength, 
                                 uint8_t* output, size_t* outputLength) {
    if (nonceSize > BLOCK_SIZE - 4) {
        return false;  // El nonce es demasiado grande
    }

    uint8_t counterBlock[BLOCK_SIZE];
    uint8_t streamBlock[BLOCK_SIZE];
    size_t nc_off = 0;

    memcpy(counterBlock, nonce, nonceSize);
    for (int i = nonceSize; i < BLOCK_SIZE - 4; i++) {
        counterBlock[i] = 0;
    }
    counterBlock[BLOCK_SIZE - 4] = (counter >> 24) & 0xFF;
    counterBlock[BLOCK_SIZE - 3] = (counter >> 16) & 0xFF;
    counterBlock[BLOCK_SIZE - 2] = (counter >> 8) & 0xFF;
    counterBlock[BLOCK_SIZE - 1] = counter & 0xFF;

    return mbedtls_aes_crypt_ctr(&m_aesContext, inputLength, &nc_off, counterBlock, streamBlock, input, output) == 0;
}

bool AESEncryption::encrypt(const uint8_t* nonce, size_t nonceSize, uint32_t counter,
                            const uint8_t* input, size_t inputLength, 
                            uint8_t* output, size_t* outputLength) {
    *outputLength = inputLength;
    return ctrOperation(nonce, nonceSize, counter, input, inputLength, output, outputLength);
}

bool AESEncryption::decrypt(const uint8_t* nonce, size_t nonceSize, uint32_t counter,
                            const uint8_t* input, size_t inputLength, 
                            uint8_t* output, size_t* outputLength) {
    // En CTR, la operación de descifrado es idéntica a la de cifrado
    return encrypt(nonce, nonceSize, counter, input, inputLength, output, outputLength);
}

void AESEncryption::encryptAndDecrypt(const char* message) {
    size_t messageLength = strlen(message);
    uint8_t* plaintext = new uint8_t[messageLength];
    uint8_t* ciphertext = new uint8_t[messageLength];
    uint8_t* decrypted = new uint8_t[messageLength];
    
    memcpy(plaintext, message, messageLength);

    // Generamos un nonce aleatorio (en un escenario real, esto debería ser único para cada mensaje)
    uint8_t nonce[12];
    for (int i = 0; i < 12; i++) {
        nonce[i] = random(256);
    }
    uint32_t counter = 1;  // Iniciamos el contador en 1

    size_t outputLength = messageLength;

    Serial.println("Mensaje original: " + String(message));

    if (encrypt(nonce, sizeof(nonce), counter, plaintext, messageLength, ciphertext, &outputLength)) {
        Serial.print("Texto cifrado: ");
        for (size_t i = 0; i < outputLength; i++) {
            Serial.printf("%02X", ciphertext[i]);
        }
        Serial.println();

        if (decrypt(nonce, sizeof(nonce), counter, ciphertext, outputLength, decrypted, &outputLength)) {
            Serial.print("Mensaje descifrado: ");
            Serial.write(decrypted, outputLength);
            Serial.println();
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