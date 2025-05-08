#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


// BLE service and characteristic UUIDs (randomly generated or your own)
#define SERVICE_UUID       "11111111-1234-1234-1234-1234567890ab"
#define AUTH_CHAR_UUID     "22222222-2222-3333-4444-555566667777"
#define DATA_CHAR_UUID     "33333333-1234-5678-90ab-cdef12345678"


BLECharacteristic *pAuthCharacteristic;
BLECharacteristic *pDataCharacteristic;
BLEAdvertising *pAdvertising; // for restart advertising

uint32_t value = 0;  // some dummy data to notify
bool deviceConnected = false;
bool isAuthenticated = false;
std::string currentClientMac = "";


bool authEnabled = false;
std::string trustedMac = "";
std::string trustedPubKey = "";

// pre-shared Public key
const char* rsa_public_key_pem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnoB5/TObnVyBvKllVhKB
zpnGoW1qJGpCLx9VQU6Yf4SU//6P4RdCYiWRfbY8PJFz4TPwiCPhNyP6deEC5Hst
kxQXTLUZvgfhv/Swy/UeE0XvUAemD6A4G7KfSOL5KApOl200kO7jF0/usojXnFYJ
IZYptIA3HL2JGGVI9xaqEHYrp4UF3J7+BaBZ8GaqqnXHyeFKA35fhBs54NxGfNRP
nisw1NOJ4jbNSse3bcHi5k1nT0W/fYca+vEQlJdw0jR5MEXIcwGigaUA0cM+eF5o
A+c5MX8kaotX2q85gfPYMZT8l906SM69UrC+OhOT3YmC2RtvdrFnVz9KEb1De6Ln
YwIDAQAB
-----END PUBLIC KEY-----)";


// Get client MAC using ESP-IDF callback
void myGattsCallback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
  if (event == ESP_GATTS_CONNECT_EVT) {
    char mac_str[18];
    sprintf(mac_str,
            "%02x:%02x:%02x:%02x:%02x:%02x",
            param->connect.remote_bda[0], param->connect.remote_bda[1],
            param->connect.remote_bda[2], param->connect.remote_bda[3],
            param->connect.remote_bda[4], param->connect.remote_bda[5]);
    currentClientMac = std::string(mac_str);
    Serial.print("\xF0\x9F\x93\xA1 Connected client MAC: ");
    Serial.println(currentClientMac.c_str());
  }
  if (event == ESP_GATTS_DISCONNECT_EVT) {
    currentClientMac = "";
    Serial.println("\xF0\x9F\x94\x8C Disconnected. MAC cleared.");
  }
}

class AuthCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) override {
    std::string raw = pCharacteristic->getValue();

    // If not authenticated yet
    if (!authEnabled) {
      if (raw.find("START_AUTH:") == 0) {
        std::string mac = raw.substr(strlen("START_AUTH:"));
        std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
        trustedMac = mac;
        authEnabled = true;
        Serial.print("Auth locked to MAC: ");
        Serial.println(trustedMac.c_str());
        pCharacteristic->setValue("LOCKED");
        return;
      } else {
        Serial.println("Auth not enabled yet. Allowing.");
        pCharacteristic->setValue("OK");
        return;
      }
    }

    if (!deviceConnected || currentClientMac.empty()) {
      pCharacteristic->setValue("FAIL");
      return;
    }

    std::string peer_mac = currentClientMac;
    std::transform(peer_mac.begin(), peer_mac.end(), peer_mac.begin(), ::tolower);
    if (peer_mac != trustedMac) {
      Serial.print("MAC mismatch. Got ");
      Serial.println(peer_mac.c_str());
      pCharacteristic->setValue("FAIL");
      return;
    }

    if (raw.size() < 3) {
      pCharacteristic->setValue("FAIL");
      return;
    }

    uint16_t msg_len = (uint8_t)raw[0] << 8 | (uint8_t)raw[1];
    if (raw.size() < 2 + msg_len + 64) {
      pCharacteristic->setValue("FAIL");
      return;
    }

    std::string message = raw.substr(2, msg_len);
    std::string signature = raw.substr(2 + msg_len);

    size_t prefix_len = strlen("authorize-rsa:");
    if (message.size() < prefix_len + 17) {
      pCharacteristic->setValue("FAIL");
      return;
    }
    std::string mac_in_msg = message.substr(prefix_len, 17);
    std::transform(mac_in_msg.begin(), mac_in_msg.end(), mac_in_msg.begin(), ::tolower);
    if (mac_in_msg != peer_mac) {
      Serial.println("MAC in message doesn't match connected MAC");
      pCharacteristic->setValue("FAIL");
      return;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk,
        (const unsigned char*)rsa_public_key_pem, strlen(rsa_public_key_pem) + 1);
    if (ret != 0) {
      Serial.println("Failed to parse stored public key");
      mbedtls_pk_free(&pk);
      pCharacteristic->setValue("FAIL");
      return;
    }

    unsigned char hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char*)message.data(), message.size(), hash);

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                            (const unsigned char*)signature.data(), signature.size());
    mbedtls_pk_free(&pk);

    if (ret == 0) {
      Serial.println("Authenticated");
      isAuthenticated = true;
      pCharacteristic->setValue("OK");
    } else {
      Serial.println("Signature failed");
      pCharacteristic->setValue("FAIL");
    }
  }
};

class DataCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    std::string val = pCharacteristic->getValue();
    Serial.print("Data written: ");
    Serial.println(val.c_str());
  }
};

class MyServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
    Serial.println("Device connected");
  }
  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
    isAuthenticated = false;
    Serial.println("Device disconnected");
    delay(100);
    pAdvertising->start();
  }
};

void setup() {
  Serial.begin(115200);
  BLEDevice::init("ESP32C3-GATT-Server");
  BLEDevice::setCustomGattsHandler(myGattsCallback);

  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pServer->createService(SERVICE_UUID);

  pAuthCharacteristic = pService->createCharacteristic(
      AUTH_CHAR_UUID, BLECharacteristic::PROPERTY_WRITE);
  pAuthCharacteristic->setCallbacks(new AuthCallbacks());

  pDataCharacteristic = pService->createCharacteristic(
      DATA_CHAR_UUID, BLECharacteristic::PROPERTY_NOTIFY |
                      BLECharacteristic::PROPERTY_READ);
  pDataCharacteristic->addDescriptor(new BLE2902());
  pDataCharacteristic->setCallbacks(new DataCallbacks());
  pDataCharacteristic->setValue("Hello BLE!");

  pService->start();
  pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->start();
  Serial.println("Waiting for client...");
}

void loop() {
  static uint32_t value = 0;
  if (deviceConnected && isAuthenticated) {
    value++;
    String msg = "Notify #" + String(value);
    pDataCharacteristic->setValue(msg.c_str());
    pDataCharacteristic->notify();
    Serial.println("Sent notify: " + msg);
    delay(5000);
  }
}






