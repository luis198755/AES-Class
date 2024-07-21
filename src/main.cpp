#include <Arduino.h>
#include "AESEncryption.h"

// Clave AES (128-bit)
const uint8_t aesKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

AESEncryption aesEncryptor;

void setup() {
    Serial.begin(115200);
    while (!Serial) {
        ; // Esperar a que se conecte el puerto serial
    }
    Serial.println("Luis Alberto Rodríguez Meneses");

    String plaintext = "Luis Alberto Rodríguez Meneses";
    Serial.println("Mensaje original: " + plaintext);

    // Encriptar
    String nonce;
    String ciphertext = aesEncryptor.encrypt(aesKey, sizeof(aesKey), plaintext, nonce);
    Serial.println("Texto cifrado: " + ciphertext);
    Serial.println("Nonce: " + nonce);

    // Desencriptar
    String decryptedText = aesEncryptor.decrypt(aesKey, sizeof(aesKey), ciphertext, nonce);
    Serial.println("Mensaje desencriptado: " + decryptedText);
}

void loop() {
    // Tu código principal aquí, para ejecutar repetidamente:
    delay(1000);
}