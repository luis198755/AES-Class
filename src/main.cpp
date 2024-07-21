#include <Arduino.h>
#include "AESEncryption.h"

// Clave AES (128-bit)
const uint8_t aesKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

// Instancia global de AESEncryption
AESEncryption aesEncryptor(aesKey, sizeof(aesKey));

void setup() {
    Serial.begin(115200);
    while (!Serial) {
        ; // Esperar a que se conecte el puerto serial
    }
    Serial.println("Ejemplo de Cifrado AES");

    // Imprimir la memoria libre
    Serial.printf("Heap libre: %d bytes\n", ESP.getFreeHeap());

    // Ejemplo de uso
    aesEncryptor.encryptAndDecrypt("Hola, ESP32! TrafficLight");
}

void loop() {
    // Tu código principal aquí, para ejecutar repetidamente:
    delay(1000);
}