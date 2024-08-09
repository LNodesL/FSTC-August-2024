#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <bcrypt.h>
#include <winerror.h>
#include <random>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

void PrintUsage() {
    std::cout << "Usage: Build.exe <path_to_original_PE> <path_to_output_encrypted_file> [32_byte_key]\n";
    std::cout << "Example: Build.exe test_payload.exe encrypted_payload.bin 0123456789abcdef0123456789abcdef\n";
}

bool ReadFile(const std::string& filePath, std::vector<BYTE>& buffer) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    buffer.resize(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return false;
    }

    return true;
}

bool WriteFile(const std::string& filePath, const std::vector<BYTE>& buffer) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

void GenerateRandomBytes(std::vector<BYTE>& buffer, size_t size) {
    buffer.resize(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        buffer[i] = static_cast<BYTE>(dis(gen));
    }
}

void PrintByteArray(const std::vector<BYTE>& buffer) {
    for (BYTE b : buffer) {
        std::printf("%02x", b);
    }
    std::cout << std::endl;
}

void PrintByteArrayInCodeFormat(const std::vector<BYTE>& buffer, const std::string& name) {
    std::cout << "BYTE " << name << "[] = { ";
    for (size_t i = 0; i < buffer.size(); ++i) {
        std::printf("0x%02x", buffer[i]);
        if (i != buffer.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << " };" << std::endl;
}

bool EncryptPayload(const std::vector<BYTE>& plainText, const std::vector<BYTE>& key, const std::vector<BYTE>& iv, std::vector<BYTE>& cipherText) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0, cbCipherText = 0;

    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptOpenAlgorithmProvider Failed With Error: " << status << std::endl;
        return false;
    }

    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptSetProperty Failed With Error: " << status << std::endl;
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return false;
    }

    status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptGenerateSymmetricKey Failed With Error: " << status << std::endl;
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return false;
    }

    status = BCryptEncrypt(hKey, (PBYTE)plainText.data(), plainText.size(), NULL, (PBYTE)iv.data(), iv.size(), NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptEncrypt (get size) Failed With Error: " << status << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return false;
    }

    cipherText.resize(cbCipherText);
    status = BCryptEncrypt(hKey, (PBYTE)plainText.data(), plainText.size(), NULL, (PBYTE)iv.data(), iv.size(), cipherText.data(), cipherText.size(), &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        std::cerr << "[!] BCryptEncrypt Failed With Error: " << status << std::endl;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        return false;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAesAlg, 0);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        PrintUsage();
        return 1;
    }

    std::string inputPath = argv[1];
    std::string outputPath = argv[2];
    std::string keyStr = argc == 4 ? argv[3] : "";

    std::vector<BYTE> key;
    if (keyStr.empty()) {
        GenerateRandomBytes(key, 32);
        std::cout << "[*] Generated random 32-byte key: ";
        PrintByteArray(key);
        PrintByteArrayInCodeFormat(key, "key");
    }
    else if (keyStr.size() == 64) {
        key.reserve(32);
        for (size_t i = 0; i < keyStr.size(); i += 2) {
            std::string byteString = keyStr.substr(i, 2);
            BYTE byte = (BYTE)strtol(byteString.c_str(), nullptr, 16);
            key.push_back(byte);
        }
    }
    else {
        std::cerr << "[!] Key must be exactly 64 hexadecimal characters if provided." << std::endl;
        return 1;
    }

    std::vector<BYTE> plainText;
    if (!ReadFile(inputPath, plainText)) {
        std::cerr << "[!] Failed to read input file." << std::endl;
        return 1;
    }

    std::vector<BYTE> iv;
    GenerateRandomBytes(iv, 16);
    std::cout << "[*] Generated random 16-byte IV: ";
    PrintByteArray(iv);
    PrintByteArrayInCodeFormat(iv, "iv");

    std::vector<BYTE> cipherText;

    if (!EncryptPayload(plainText, key, iv, cipherText)) {
        std::cerr << "[!] Encryption failed." << std::endl;
        return 1;
    }

    if (!WriteFile(outputPath, cipherText)) {
        std::cerr << "[!] Failed to write encrypted file." << std::endl;
        return 1;
    }

    std::cout << "[*] File encrypted successfully." << std::endl;
    return 0;
}
